//
//  HkdfGuardKeyProtectionEnclaveTests.swift
//  HkdfGuardKeyProtectionEnclaveTests
//

import Testing
import Foundation
import Security
@testable import HkdfGuardKeyProtectionEnclave

/// Exercises the public C-ABI entry points exposed by
/// `HkdfGuardKeyProtectionEnclave.h` — `hkdfguard_wrap_dek` and
/// `hkdfguard_unwrap_dek`. Both are `@_cdecl` functions, but they're still
/// ordinary `public` Swift functions underneath, so they can be called
/// directly here without any C interop.
///
/// These status codes are the module's private `HKDFGuardStatus` raw
/// values, mirrored here since that enum isn't visible outside the module:
///   0 = success, -1 = invalidInputLength, -2 = outputBufferTooSmall,
///   -3 = keyUnavailable, -6 = decryptionFailed, -8 = missingServiceIdentifier.
///
/// This suite runs serialized (`.serialized` below), not in parallel:
/// Swift Testing's default per-test parallelism was observed to hang the
/// whole run — many tests simultaneously calling into the real Secure
/// Enclave Processor (visible in a stack sample as multiple threads
/// piled up inside `TKSEPClientTokenSession`/`TKSEPKey`) apparently
/// exceeds whatever concurrency the SEP/securityd IPC layer actually
/// supports, well short of a hardware or App Sandbox limit we're
/// deliberately imposing. Each test still uses its own distinct service
/// identifier (rather than one shared default) so failures stay isolated
/// and easy to attribute to a specific test even though everything now
/// runs one at a time. Every test that actually provisions a Secure
/// Enclave key registers a `defer` to delete that key's keychain item
/// immediately after declaring the service string it'll use — `defer`
/// runs on every exit path, including a failed `#expect`, so a failing
/// test still leaves the keychain clean.
@Suite(.serialized)
struct HkdfGuardKeyProtectionEnclaveWrapUnwrapTests {

    // MARK: - Helpers

    private static let dekLength = 32
    private static let wrappedLength = 124 // 64-byte ephemeral pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag

    private static func randomDEK() -> [UInt8] {
        (0..<dekLength).map { _ in UInt8.random(in: .min ... .max) }
    }

    /// Deletes the keychain item backing a service's Secure Enclave key,
    /// if one was created. There's no separate "delete this SE key" API —
    /// the SE key becomes unreferenced (and its `dataRepresentation` can
    /// never be reconstructed again) once the keychain item that stores
    /// that representation is gone, which is the actual cleanup unit here.
    private static func deleteKEK(service: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: hkdfguardKeychainAccount
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func wrap(
        _ dek: [UInt8],
        service: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, wrapped: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = service.withCString { serviceCStr in
            dek.withUnsafeBufferPointer { dekBuf in
                out.withUnsafeMutableBufferPointer { outBuf in
                    hkdfguard_wrap_dek(
                        servicePtr: serviceCStr,
                        dekPtr: dekBuf.baseAddress!,
                        dekLen: Int32(dek.count),
                        outPtr: outBuf.baseAddress!,
                        outLen: &outLen
                    )
                }
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    private static func unwrap(
        _ wrapped: [UInt8],
        service: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, plaintext: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = service.withCString { serviceCStr in
            wrapped.withUnsafeBufferPointer { wrappedBuf in
                out.withUnsafeMutableBufferPointer { outBuf in
                    hkdfguard_unwrap_dek(
                        servicePtr: serviceCStr,
                        wrappedPtr: wrappedBuf.baseAddress!,
                        wrappedLen: Int32(wrapped.count),
                        outPtr: outBuf.baseAddress!,
                        outLen: &outLen
                    )
                }
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    // MARK: - Round trip

    @Test func wrapThenUnwrapRecoversOriginalDEK() {
        let service = "com.hkdfguard.tests.roundtrip"
        defer { Self.deleteKEK(service: service) }
        let dek = Self.randomDEK()

        let wrapResult = Self.wrap(dek, service: service)
        #expect(wrapResult.status == 0)

        let unwrapResult = Self.unwrap(wrapResult.wrapped, service: service)
        #expect(unwrapResult.status == 0)
        #expect(unwrapResult.plaintext == dek)
    }

    @Test func wrappedOutputHasExpectedLength() {
        let service = "com.hkdfguard.tests.wrapped-length"
        defer { Self.deleteKEK(service: service) }

        let result = Self.wrap(Self.randomDEK(), service: service)
        #expect(result.status == 0)
        #expect(result.wrapped.count == Self.wrappedLength)
    }

    @Test func twoWrapsOfSameDEKProduceDifferentCiphertext() {
        // Each wrap uses a fresh ephemeral key + random AES-GCM nonce, so
        // wrapping the same DEK twice must never produce identical output —
        // this is what makes the scheme semantically secure rather than
        // just "encrypted."
        let service = "com.hkdfguard.tests.nonce-uniqueness"
        defer { Self.deleteKEK(service: service) }
        let dek = Self.randomDEK()
        let first = Self.wrap(dek, service: service)
        let second = Self.wrap(dek, service: service)

        #expect(first.status == 0)
        #expect(second.status == 0)
        #expect(first.wrapped != second.wrapped)
    }

    // MARK: - Service identifier behavior

    @Test func differentServicesGetIsolatedKeys() {
        // Each service string is meant to identify a distinct calling
        // application; wrapping under one service's KEK and unwrapping
        // under a different service's KEK must fail, not silently
        // succeed against the wrong key.
        let serviceA = "com.hkdfguard.tests.appA"
        let serviceB = "com.hkdfguard.tests.appB"
        defer {
            Self.deleteKEK(service: serviceA)
            Self.deleteKEK(service: serviceB)
        }

        let dek = Self.randomDEK()
        let wrapResult = Self.wrap(dek, service: serviceA)
        #expect(wrapResult.status == 0)

        let crossServiceResult = Self.unwrap(wrapResult.wrapped, service: serviceB)
        #expect(crossServiceResult.status != 0)
    }

    @Test func wrapRejectsEmptyServiceIdentifier() {
        // No defer/cleanup needed: an empty service is rejected before any
        // key provisioning happens, so nothing is ever created.
        let result = Self.wrap(Self.randomDEK(), service: "")
        #expect(result.status == -8) // missingServiceIdentifier
    }

    @Test func unwrapRejectsEmptyServiceIdentifier() {
        let setupService = "com.hkdfguard.tests.empty-service-unwrap-setup"
        defer { Self.deleteKEK(service: setupService) }

        let wrapped = Self.wrap(Self.randomDEK(), service: setupService).wrapped
        let result = Self.unwrap(wrapped, service: "")
        #expect(result.status == -8) // missingServiceIdentifier
    }

    @Test func concurrentFirstUseOfSameServiceConvergesOnOneKEK() {
        // Regression test: getOrCreateKEK() used to report keyUnavailable
        // (-3) non-deterministically when multiple callers raced to
        // create the very first keychain item for a service at the same
        // time (SecItemAdd's unique index on service+account lets only
        // one caller's create win; the rest must fall back to loading the
        // winner's key rather than treating that as failure). Using a
        // never-before-seen service identifier here forces every task
        // through that first-use race on every run.
        //
        // This deliberately uses DispatchQueue.concurrentPerform (real OS
        // threads from GCD's pool) rather than Swift's async/withTaskGroup:
        // hkdfguard_wrap_dek makes synchronous, blocking Security-framework
        // calls, and Swift Concurrency's cooperative thread pool has a
        // limited number of threads that assume tasks suspend via `await`
        // rather than block outright. Spawning several blocking calls via
        // withTaskGroup here — on top of Swift Testing's own default
        // per-test parallelism — was enough to exhaust that pool and
        // deadlock the entire test run, observed directly (every thread
        // parked in the Testing runner's scheduler, no forward progress).
        // GCD's pool is designed for exactly this kind of blocking work.
        let service = "com.hkdfguard.tests.concurrent-first-use.\(UUID().uuidString)"
        defer { Self.deleteKEK(service: service) }
        let dek = Self.randomDEK()

        let lock = NSLock()
        var statuses: [Int32] = []

        // 3 concurrent creators is enough to exercise the unique-index
        // race (needs >=2); observed directly that pushing much more
        // simultaneous load at the real Secure Enclave/securityd IPC
        // layer causes severe contention on this hardware, so this stays
        // deliberately modest rather than maximizing concurrency.
        DispatchQueue.concurrentPerform(iterations: 3) { _ in
            let status = Self.wrap(dek, service: service).status
            lock.lock()
            statuses.append(status)
            lock.unlock()
        }

        #expect(statuses.count == 3)
        #expect(statuses.allSatisfy { $0 == 0 })
    }

    // MARK: - Input validation

    @Test func wrapRejectsIncorrectDEKLength() {
        // No defer/cleanup needed: the DEK-length check runs before any
        // key provisioning, so nothing is ever created.
        let tooShort = [UInt8](repeating: 0, count: 16)
        let result = Self.wrap(tooShort, service: "com.hkdfguard.tests.bad-dek-length")
        #expect(result.status == -1) // invalidInputLength
    }

    @Test func unwrapRejectsBlobShorterThanEphemeralKey() {
        // No defer/cleanup needed: the length check runs before any key
        // provisioning, so nothing is ever created.
        let tooShort = [UInt8](repeating: 0, count: 32)
        let result = Self.unwrap(tooShort, service: "com.hkdfguard.tests.short-blob")
        #expect(result.status == -1) // invalidInputLength
    }

    // MARK: - Output buffer sizing

    @Test func wrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.wrap-buffer-too-small"
        defer { Self.deleteKEK(service: service) }

        let result = Self.wrap(Self.randomDEK(), service: service, bufferCapacity: 10)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.wrappedLength))
    }

    @Test func unwrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.unwrap-buffer-too-small"
        defer { Self.deleteKEK(service: service) }

        let wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        let result = Self.unwrap(wrapped, service: service, bufferCapacity: 4)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.dekLength))
    }

    // MARK: - Tamper detection

    @Test func unwrapRejectsTamperedCiphertext() {
        let service = "com.hkdfguard.tests.tamper-detection"
        defer { Self.deleteKEK(service: service) }

        var wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        // Flip a bit inside the AES-GCM ciphertext/tag region (well past
        // the 64-byte ephemeral public key prefix).
        wrapped[wrapped.count - 1] ^= 0xFF

        let result = Self.unwrap(wrapped, service: service)
        #expect(result.status == -6) // decryptionFailed — the GCM tag check must catch this
    }

    @Test func unwrapRejectsGarbageInput() {
        // Unlike the length-check-only validation tests above, this blob
        // is a full 124 bytes, so it passes the length/service checks and
        // does reach key provisioning before failing to parse/decrypt.
        let service = "com.hkdfguard.tests.garbage-input"
        defer { Self.deleteKEK(service: service) }

        let garbage = (0..<Self.wrappedLength).map { UInt8($0 & 0xFF) }
        let result = Self.unwrap(garbage, service: service)
        #expect(result.status != 0)
    }
}
