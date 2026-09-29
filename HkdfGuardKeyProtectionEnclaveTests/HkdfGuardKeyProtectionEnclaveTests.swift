//
//  HkdfGuardKeyProtectionEnclaveTests.swift
//  HkdfGuardKeyProtectionEnclaveTests
//

import Testing
import Foundation
import CryptoKit
import Security
@testable import HkdfGuardKeyProtectionEnclave

/// Exercises the public C-ABI entry points exposed by
/// `HkdfGuardKeyProtectionEnclave.h` — `hkdfguard_kek_exists`,
/// `hkdfguard_create_kek`, `hkdfguard_wrap_dek`, `hkdfguard_unwrap_dek`, and
/// `hkdfguard_generate_and_wrap_dek`. All are `@_cdecl` functions, but
/// they're still ordinary `public` Swift functions underneath, so they can
/// be called directly here without any C interop.
///
/// These status codes are the module's private `HKDFGuardStatus` raw
/// values, mirrored here since that enum isn't visible outside the module:
///   0 = success, -1 = invalidInputLength, -2 = outputBufferTooSmall,
///   -3 = keyUnavailable (reserved, no longer returned), -6 = decryptionFailed,
///   -8 = invalidServiceIdentifier, -9 = enclaveUnavailable,
///   -10 = kekNotFound, -11 = kekCorrupted, -12 = accessControlCreationFailed,
///   -13 = keyGenerationFailed, -14 = keychainWriteFailed,
///   -15 = kekVerificationFailed, -16 = fingerprintMismatch,
///   -17 = keychainAccessDenied, -18 = keychainReadFailed.
///
/// Important behavior change worth calling out here, not just in the
/// individual tests below: `hkdfguard_wrap_dek`/`hkdfguard_unwrap_dek`/
/// `hkdfguard_generate_and_wrap_dek` no longer create a KEK on first use —
/// that's the entire point of splitting `hkdfguard_kek_exists`/
/// `hkdfguard_create_kek` out as their own calls (see
/// HkdfGuardKeyProtectionEnclave.swift's `createKEK`/`kekExists`). Every
/// test below that expects a wrap/unwrap/generate-and-wrap to actually
/// *succeed* therefore calls `Self.createKEK(service:)` first and asserts
/// it returns success, exactly as real calling code now must.
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
///
/// Service name charset: `hkdfguard_kek_exists`/`hkdfguard_create_kek`/
/// `hkdfguard_wrap_dek`/`hkdfguard_unwrap_dek`/
/// `hkdfguard_generate_and_wrap_dek` all validate `service` via
/// `validServiceName` — ASCII letters, digits, and `.` only, 1-128
/// characters — so every service literal below deliberately uses `.` in
/// place of the `-`/`_` this suite's names might otherwise read more
/// naturally with (e.g. `wrapped.length`, not `wrapped-length`), and
/// nowhere relies on `UUID().uuidString` verbatim (its dashes would fail
/// validation too).
@Suite(
    .serialized,
    .enabled(
        if: SecureEnclave.isAvailable,
        "requires a real Secure Enclave — not available on CI/VM runners (e.g. GitHub-hosted macOS runners, where Apple's Virtualization framework doesn't pass the Secure Enclave through to the guest); run this suite on real Mac hardware before committing/requesting a build"
    )
)
struct HkdfGuardKeyProtectionEnclaveWrapUnwrapTests {

    // MARK: - Helpers

    private static let dekLength = 32
    private static let wrappedLength = 156 // 32-byte KEK fingerprint + 64-byte ephemeral pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag
    private static let maxServiceNameLength = 128

    private static func randomDEK() -> [UInt8] {
        (0..<dekLength).map { _ in UInt8.random(in: .min ... .max) }
    }

    /// Deletes the keychain item backing a service's Secure Enclave key,
    /// if one was created. There's no separate "delete this SE key" API —
    /// the SE key becomes unreferenced (and its `dataRepresentation` can
    /// never be reconstructed again) once the keychain item that stores
    /// that representation is gone, which is the actual cleanup unit here.
    private static func deleteKEK(service: String) {
        // The library lowercases `service` before storing (see
        // `normalizedService`), and legacy-keychain service matching is
        // case-sensitive — deleting with the caller's original spelling
        // (`appA`, an uppercase UUID) silently misses and leaks the item.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service.lowercased(),
            kSecAttrAccount as String: hkdfguardKeychainAccount
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func kekExists(service: String) -> (status: Int32, exists: Bool) {
        var outExists: Int32 = -1
        let status = service.withCString { serviceCStr in
            hkdfguard_kek_exists(servicePtr: serviceCStr, outExists: &outExists)
        }
        return (status, outExists != 0)
    }

    @discardableResult
    private static func createKEK(service: String) -> Int32 {
        service.withCString { serviceCStr in
            hkdfguard_create_kek(servicePtr: serviceCStr)
        }
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

    private static func generateAndWrap(
        service: String,
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, wrapped: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = service.withCString { serviceCStr in
            out.withUnsafeMutableBufferPointer { outBuf in
                hkdfguard_generate_and_wrap_dek(
                    servicePtr: serviceCStr,
                    outPtr: outBuf.baseAddress!,
                    outLen: &outLen
                )
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    // MARK: - hkdfguard_kek_exists / hkdfguard_create_kek

    @Test func kekExistsReportsFalseForNeverCreatedService() {
        let service = "com.hkdfguard.tests.kek.exists.never.created"
        // No defer/cleanup needed: this service is never created by this
        // test, only queried.
        let result = Self.kekExists(service: service)
        #expect(result.status == 0)
        #expect(result.exists == false)
    }

    @Test func createKekThenKekExistsReportsTrue() {
        let service = "com.hkdfguard.tests.kek.exists.after.create"
        defer { Self.deleteKEK(service: service) }

        #expect(Self.createKEK(service: service) == 0)

        let result = Self.kekExists(service: service)
        #expect(result.status == 0)
        #expect(result.exists == true)
    }

    @Test func createKekIsIdempotent() {
        // Calling create twice must succeed both times, not treat the
        // second call as an error just because a key already exists —
        // that's the whole point of it being "create if missing," not
        // "create or fail."
        let service = "com.hkdfguard.tests.kek.create.idempotent"
        defer { Self.deleteKEK(service: service) }

        #expect(Self.createKEK(service: service) == 0)
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.kekExists(service: service)
        #expect(result.status == 0)
        #expect(result.exists == true)
    }

    @Test func concurrentFirstUseOfCreateKekConvergesOnOneKEK() {
        // Regression test: createKEK() used to report keyUnavailable (-3)
        // non-deterministically when multiple callers raced to create the
        // very first keychain item for a service at the same time
        // (SecItemAdd's unique index on service+account lets only one
        // caller's create win; the rest must fall back to loading the
        // winner's key rather than treating that as failure). This race
        // used to be exercised through hkdfguard_wrap_dek itself, back
        // when wrap implicitly created a missing KEK — now that creation
        // is its own call, this exercises hkdfguard_create_kek directly,
        // which is where that logic actually lives today. Using a
        // never-before-seen service identifier here forces every task
        // through that first-use race on every run.
        //
        // This deliberately uses DispatchQueue.concurrentPerform (real OS
        // threads from GCD's pool) rather than Swift's async/withTaskGroup:
        // hkdfguard_create_kek makes synchronous, blocking
        // Security-framework calls, and Swift Concurrency's cooperative
        // thread pool has a limited number of threads that assume tasks
        // suspend via `await` rather than block outright. Spawning several
        // blocking calls via withTaskGroup here — on top of Swift
        // Testing's own default per-test parallelism — was enough to
        // exhaust that pool and deadlock the entire test run, observed
        // directly (every thread parked in the Testing runner's
        // scheduler, no forward progress). GCD's pool is designed for
        // exactly this kind of blocking work.
        //
        // Service names must stay within the letters/digits/'.' charset —
        // unlike the old version of this test, this can't suffix a raw
        // UUID (its dashes would be rejected), so it strips them instead.
        let service = "com.hkdfguard.tests.kek.create.concurrent.\(UUID().uuidString.filter { $0 != "-" })"
        defer { Self.deleteKEK(service: service) }

        let lock = NSLock()
        var statuses: [Int32] = []

        // 3 concurrent creators is enough to exercise the unique-index
        // race (needs >=2); observed directly that pushing much more
        // simultaneous load at the real Secure Enclave/securityd IPC
        // layer causes severe contention on this hardware, so this stays
        // deliberately modest rather than maximizing concurrency.
        DispatchQueue.concurrentPerform(iterations: 3) { _ in
            let status = Self.createKEK(service: service)
            lock.lock()
            statuses.append(status)
            lock.unlock()
        }

        #expect(statuses.count == 3)
        #expect(statuses.allSatisfy { $0 == 0 })
    }

    @Test func kekExistsRejectsInvalidServiceIdentifier() {
        // No defer/cleanup needed: rejected before any key provisioning
        // or lookup happens.
        let result = Self.kekExists(service: "")
        #expect(result.status == -8) // invalidServiceIdentifier
        #expect(result.exists == false)
    }

    @Test func createKekRejectsInvalidServiceIdentifier() {
        // No defer/cleanup needed: rejected before any key provisioning
        // happens.
        #expect(Self.createKEK(service: "") == -8) // invalidServiceIdentifier
    }

    @Test func createKekAcceptsServiceNameAtMaxLength() {
        let service = String(repeating: "a", count: Self.maxServiceNameLength)
        defer { Self.deleteKEK(service: service) }

        #expect(Self.createKEK(service: service) == 0)
        #expect(Self.kekExists(service: service).exists == true)
    }

    @Test func createKekRejectsServiceNameOverMaxLength() {
        // No defer/cleanup needed: rejected before any key provisioning
        // happens.
        let tooLong = String(repeating: "a", count: Self.maxServiceNameLength + 1)
        #expect(Self.createKEK(service: tooLong) == -8) // invalidServiceIdentifier

        let result = Self.kekExists(service: tooLong)
        #expect(result.status == -8) // invalidServiceIdentifier
        #expect(result.exists == false)
    }

    @Test func createKekRejectsServiceNameWithDisallowedCharacters() {
        // No defer/cleanup needed: rejected before any key provisioning
        // happens. Only ASCII letters, digits, and '.' are accepted — a
        // hyphen (still a very ordinary character in a reverse-DNS-style
        // identifier) must not slip through.
        #expect(Self.createKEK(service: "com.hkdfguard.tests-invalid-charset") == -8) // invalidServiceIdentifier
    }

    @Test func serviceNameIsCaseInsensitive() {
        // The library lowercases before every keychain/crypto use, so the
        // same KEK must be reached however the caller capitalizes.
        let mixed = "Com.HkdfGuard.Tests.Case.Insensitive"
        let lower = mixed.lowercased()
        defer { Self.deleteKEK(service: lower) }

        #expect(Self.createKEK(service: mixed) == 0)
        #expect(Self.kekExists(service: lower).exists == true)

        let wrapped = Self.wrap(Self.randomDEK(), service: mixed)
        #expect(wrapped.status == 0)
        #expect(Self.unwrap(wrapped.wrapped, service: lower).status == 0)
        #expect(Self.unwrap(wrapped.wrapped, service: mixed.uppercased()).status == 0)
    }

    @Test func serviceNameRejectsNonASCII() {
        // Character.isLetter/isNumber would accept every one of these; the
        // contract (header, CLI, Linux tool) is ASCII bytes only. The
        // KELVIN SIGN case matters most: Unicode-lowercased it becomes a
        // plain ASCII 'k', so validating *after* lowercasing would let it
        // through as a different spelling of an ASCII name.
        let rejected = [
            "caf\u{00E9}",                        // é
            "\u{65E5}\u{672C}",                   // 日本
            "com.hkdfguard.\u{0663}",             // Arabic-Indic digit three
            "com.hkdfguard.tests.\u{00BD}",       // ½
            "\u{212A}",                           // KELVIN SIGN
            "com.hkdfguard.tests.\u{0130}",       // İ (lowercases to i + U+0307)
        ]
        for name in rejected {
            #expect(Self.createKEK(service: name) == -8, "\(name.unicodeScalars.map { String($0.value, radix: 16) }) must be rejected")
            #expect(Self.kekExists(service: name).status == -8)
            #expect(Self.wrap(Self.randomDEK(), service: name).status == -8)
            #expect(Self.generateAndWrap(service: name).status == -8)
            #expect(Self.unwrap([UInt8](repeating: 0, count: Self.wrappedLength), service: name).status == -8)
        }
    }

    // MARK: - Keychain mode (hybrid)

    @Test func keychainModeInTheTestHostIsLegacy() {
        // The xctest agent carries only `com.apple.security.get-task-allow`
        // -- no `keychain-access-groups` -- so the library must pick the
        // legacy login keychain here, and that is the mode every other test
        // in this suite exercises. (Exercising the data-protection mode for
        // real needs a Team-signed host app with a provisioning profile.)
        var mode: Int32 = -1
        #expect(hkdfguard_keychain_mode(outMode: &mode) == 0)
        #expect(mode == 0)
        #expect(hkdfguardKeychainMode == .legacy)
    }

    @Test func dataProtectionModeWithoutEntitlementIsAccessDeniedNotNotFound() {
        // Drives the internal functions in data-protection mode from this
        // unentitled process. securityd answers errSecMissingEntitlement
        // (-34018); the library must report that as keychainAccessDenied
        // (-17) on every path -- never as "no key" (which would invite
        // creating one) and never as a generic failure -- and must create
        // nothing. This is also the proof that kSecUseDataProtectionKeychain
        // actually reaches the keychain calls: in legacy mode the same
        // service would simply be created.
        let service = "com.hkdfguard.tests.dataprotection.unentitled"
        defer { Self.deleteKEK(service: service) }
        let dp = KeychainMode.dataProtection(accessGroup: "MFW3T8R8J3.com.hkdfguard.keys")

        // Module-qualified: this suite's own static `kekExists`/`createKEK`
        // helpers (which go through the C ABI, in the process's real mode)
        // would otherwise shadow the library's internal functions.
        let exists = HkdfGuardKeyProtectionEnclave.kekExists(service: service, mode: dp)
        #expect(exists.status == -17)
        #expect(exists.exists == false)

        #expect(HkdfGuardKeyProtectionEnclave.createKEK(service: service, mode: dp) == -17)

        let got = HkdfGuardKeyProtectionEnclave.getKEK(service: service, mode: dp)
        #expect(got.status == -17)
        #expect(got.key == nil)

        // Nothing leaked into the legacy keychain either.
        #expect(Self.kekExists(service: service).exists == false)
    }

    @Test func corruptKeychainItemIsReportedAsKekCorruptedNotNotFound() {
        // An item exists under this service, but its data is not a Secure
        // Enclave key representation. Every entry point must report
        // kekCorrupted (-11): not "no key" (which would invite creating a
        // replacement on top of it), not success, and nothing may "heal"
        // it by replacing it. This is the case the keychain-lookup mapping
        // has to keep distinct from keychainAccessDenied (-17), which is
        // not reproducible in-process without locking the login keychain.
        let service = "com.hkdfguard.tests.kek.corrupt.item"
        defer { Self.deleteKEK(service: service) }

        let garbage = Data((0..<48).map { UInt8($0) })
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: hkdfguardKeychainAccount,
            kSecValueData as String: garbage
        ]
        #expect(SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess)

        let exists = Self.kekExists(service: service)
        #expect(exists.status == -11) // kekCorrupted
        #expect(exists.exists == false)
        #expect(Self.createKEK(service: service) == -11)
        #expect(Self.wrap(Self.randomDEK(), service: service).status == -11)
        #expect(Self.unwrap([UInt8](repeating: 0, count: Self.wrappedLength), service: service).status == -11)

        // Still corrupt, still present: createKEK above must not have
        // replaced it.
        #expect(Self.kekExists(service: service).status == -11)
    }

    // MARK: - wrap/unwrap require an already-created KEK

    @Test func wrapFailsWithKekNotFoundWhenNoKekWasCreated() {
        // The core behavior change this split is all about: wrap no
        // longer creates a KEK on first use. A well-formed, never-created
        // service must fail with kekNotFound, not succeed by silently
        // provisioning one.
        let service = "com.hkdfguard.tests.wrap.without.create"
        // No defer/cleanup needed: hkdfguard_wrap_dek must not create
        // anything here — that's exactly what's under test.
        let result = Self.wrap(Self.randomDEK(), service: service)
        #expect(result.status == -10) // kekNotFound
    }

    @Test func unwrapFailsWithKekNotFoundWhenNoKekWasCreated() {
        let service = "com.hkdfguard.tests.unwrap.without.create"
        // No defer/cleanup needed: hkdfguard_unwrap_dek must not create
        // anything here either.
        //
        // The KEK lookup now happens before the fingerprint/ephemeral-key/
        // SealedBox are even parsed, so content doesn't matter here —
        // only that the blob is longer than the fixed 96-byte
        // fingerprint+ephemeral-key prefix, matching any real wrapped
        // payload's minimum shape.
        let arbitraryBlob = [UInt8](repeating: 0, count: Self.wrappedLength)
        let result = Self.unwrap(arbitraryBlob, service: service)
        #expect(result.status == -10) // kekNotFound
    }

    // MARK: - Round trip

    @Test func wrapThenUnwrapRecoversOriginalDEK() {
        let service = "com.hkdfguard.tests.roundtrip"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)
        let dek = Self.randomDEK()

        let wrapResult = Self.wrap(dek, service: service)
        #expect(wrapResult.status == 0)

        let unwrapResult = Self.unwrap(wrapResult.wrapped, service: service)
        #expect(unwrapResult.status == 0)
        #expect(unwrapResult.plaintext == dek)
    }

    @Test func wrappedOutputHasExpectedLength() {
        let service = "com.hkdfguard.tests.wrapped.length"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.wrap(Self.randomDEK(), service: service)
        #expect(result.status == 0)
        #expect(result.wrapped.count == Self.wrappedLength)
    }

    @Test func twoWrapsOfSameDEKProduceDifferentCiphertext() {
        // Each wrap uses a fresh ephemeral key + random AES-GCM nonce, so
        // wrapping the same DEK twice must never produce identical output —
        // this is what makes the scheme semantically secure rather than
        // just "encrypted."
        let service = "com.hkdfguard.tests.nonce.uniqueness"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)
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
        #expect(Self.createKEK(service: serviceA) == 0)
        #expect(Self.createKEK(service: serviceB) == 0)

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
        #expect(result.status == -8) // invalidServiceIdentifier
    }

    @Test func unwrapRejectsEmptyServiceIdentifier() {
        let setupService = "com.hkdfguard.tests.empty.service.unwrap.setup"
        defer { Self.deleteKEK(service: setupService) }
        #expect(Self.createKEK(service: setupService) == 0)

        let wrapped = Self.wrap(Self.randomDEK(), service: setupService).wrapped
        let result = Self.unwrap(wrapped, service: "")
        #expect(result.status == -8) // invalidServiceIdentifier
    }

    // MARK: - Input validation

    @Test func wrapRejectsIncorrectDEKLength() {
        // No defer/cleanup needed: the DEK-length check runs before any
        // key provisioning (wrapDekCore checks it before ever calling
        // getKEK), so nothing is ever created even without a prior
        // hkdfguard_create_kek call here.
        let tooShort = [UInt8](repeating: 0, count: 16)
        let result = Self.wrap(tooShort, service: "com.hkdfguard.tests.bad.dek.length")
        #expect(result.status == -1) // invalidInputLength
    }

    @Test func unwrapRejectsBlobShorterThanEphemeralKey() {
        // No defer/cleanup needed: the length check runs before any key
        // provisioning, so nothing is ever created.
        let tooShort = [UInt8](repeating: 0, count: 32)
        let result = Self.unwrap(tooShort, service: "com.hkdfguard.tests.short.blob")
        #expect(result.status == -1) // invalidInputLength
    }

    @Test func unwrapRejectsAnyLengthOtherThanTheExactWrappedLength() {
        // Every payload this library produces is exactly wrappedLength
        // bytes, so one byte more or less is rejected up front -- before
        // the service is even looked at (no KEK exists for this service,
        // yet the answer is -1, not -10).
        for length in [Self.wrappedLength - 1, Self.wrappedLength + 1, Self.wrappedLength * 2] {
            let blob = [UInt8](repeating: 0, count: length)
            let result = Self.unwrap(blob, service: "com.hkdfguard.tests.inexact.length")
            #expect(result.status == -1, "length \(length)")
        }
    }

    @Test func nullPointersAreReportedNotDereferenced() {
        // A NULL from a C caller is a contract violation, but the library
        // must report it -- -1 for buffers/lengths, -8 for the service --
        // rather than crash the host process.
        var outLen: Int32 = 1024
        var out = [UInt8](repeating: 0, count: 1024)
        var exists: Int32 = -1
        let dek = Self.randomDEK()
        let blob = [UInt8](repeating: 0, count: Self.wrappedLength)

        #expect(hkdfguard_keychain_mode(outMode: nil) == -1)
        #expect(hkdfguard_kek_exists(servicePtr: nil, outExists: &exists) == -8)
        #expect(exists == 0, "outExists must still be written")
        #expect(hkdfguard_kek_exists(servicePtr: "com.hkdfguard.tests.null", outExists: nil) == -1)
        #expect(hkdfguard_create_kek(servicePtr: nil) == -8)

        out.withUnsafeMutableBufferPointer { outBuf in
            dek.withUnsafeBufferPointer { dekBuf in
                blob.withUnsafeBufferPointer { blobBuf in
                    #expect(hkdfguard_wrap_dek(servicePtr: nil, dekPtr: dekBuf.baseAddress, dekLen: 32, outPtr: outBuf.baseAddress, outLen: &outLen) == -8)
                    #expect(hkdfguard_wrap_dek(servicePtr: "com.hkdfguard.tests.null", dekPtr: nil, dekLen: 32, outPtr: outBuf.baseAddress, outLen: &outLen) == -1)
                    #expect(hkdfguard_wrap_dek(servicePtr: "com.hkdfguard.tests.null", dekPtr: dekBuf.baseAddress, dekLen: 32, outPtr: nil, outLen: &outLen) == -1)
                    #expect(hkdfguard_wrap_dek(servicePtr: "com.hkdfguard.tests.null", dekPtr: dekBuf.baseAddress, dekLen: 32, outPtr: outBuf.baseAddress, outLen: nil) == -1)
                    #expect(hkdfguard_generate_and_wrap_dek(servicePtr: nil, outPtr: outBuf.baseAddress, outLen: &outLen) == -8)
                    #expect(hkdfguard_generate_and_wrap_dek(servicePtr: "com.hkdfguard.tests.null", outPtr: nil, outLen: &outLen) == -1)
                    #expect(hkdfguard_unwrap_dek(servicePtr: nil, wrappedPtr: blobBuf.baseAddress, wrappedLen: Int32(Self.wrappedLength), outPtr: outBuf.baseAddress, outLen: &outLen) == -8)
                    #expect(hkdfguard_unwrap_dek(servicePtr: "com.hkdfguard.tests.null", wrappedPtr: nil, wrappedLen: Int32(Self.wrappedLength), outPtr: outBuf.baseAddress, outLen: &outLen) == -1)
                    #expect(hkdfguard_unwrap_dek(servicePtr: "com.hkdfguard.tests.null", wrappedPtr: blobBuf.baseAddress, wrappedLen: Int32(Self.wrappedLength), outPtr: outBuf.baseAddress, outLen: nil) == -1)
                }
            }
        }
        #expect(Self.kekExists(service: "com.hkdfguard.tests.null").exists == false, "nothing may have been created")
    }

    // MARK: - Output buffer sizing

    @Test func wrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.wrap.buffer.too.small"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.wrap(Self.randomDEK(), service: service, bufferCapacity: 10)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.wrappedLength))
    }

    @Test func unwrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.unwrap.buffer.too.small"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        let result = Self.unwrap(wrapped, service: service, bufferCapacity: 4)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.dekLength))
    }

    @Test func bufferSizingIsReportedBeforeAnyKeychainOrEnclaveWork() {
        // Output sizes are constants, so a too-small buffer must be
        // reported first -- here, for a service that has no KEK at all, the
        // answer is outputBufferTooSmall with the required size, not
        // kekNotFound. A sizing call therefore costs nothing, and unwrap
        // never decrypts a DEK for a caller who cannot receive it.
        let service = "com.hkdfguard.tests.sizing.before.kek"
        // No defer/cleanup needed: nothing is provisioned.

        let wrap = Self.wrap(Self.randomDEK(), service: service, bufferCapacity: 10)
        #expect(wrap.status == -2)
        #expect(wrap.requiredLen == Int32(Self.wrappedLength))

        let generate = Self.generateAndWrap(service: service, bufferCapacity: 10)
        #expect(generate.status == -2)
        #expect(generate.requiredLen == Int32(Self.wrappedLength))

        let blob = [UInt8](repeating: 0, count: Self.wrappedLength)
        let unwrap = Self.unwrap(blob, service: service, bufferCapacity: 4)
        #expect(unwrap.status == -2)
        #expect(unwrap.requiredLen == Int32(Self.dekLength))

        #expect(Self.kekExists(service: service).exists == false)
    }

    // MARK: - Tamper detection

    @Test func unwrapRejectsTamperedCiphertext() {
        let service = "com.hkdfguard.tests.tamper.detection"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        var wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        // Flip a bit inside the AES-GCM ciphertext/tag region (well past
        // the fingerprint + ephemeral-public-key prefix), leaving the
        // fingerprint itself untouched so this exercises the AES-GCM tag
        // check specifically, not the fingerprint check.
        wrapped[wrapped.count - 1] ^= 0xFF

        let result = Self.unwrap(wrapped, service: service)
        #expect(result.status == -6) // decryptionFailed — the GCM tag check must catch this
    }

    @Test func unwrapRejectsTamperedFingerprint() {
        // Distinct from tamper detection on the ciphertext above: flipping
        // a bit inside the fingerprint itself (the payload's leading 32
        // bytes) must be caught by the fingerprint comparison specifically
        // — before AES-GCM is even attempted — and report
        // fingerprintMismatch, not decryptionFailed.
        let service = "com.hkdfguard.tests.tamper.fingerprint"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        var wrapped = Self.wrap(Self.randomDEK(), service: service).wrapped
        wrapped[0] ^= 0xFF

        let result = Self.unwrap(wrapped, service: service)
        #expect(result.status == -16) // fingerprintMismatch
    }

    @Test func unwrapRejectsGarbageInput() {
        // Unlike the length-check-only validation tests above, this blob
        // is a full wrappedLength bytes, so it passes the length/service
        // checks. No KEK is created for this service, so this is expected
        // to fail with kekNotFound rather than reach the fingerprint check
        // or decryption — either way, it must not succeed.
        let service = "com.hkdfguard.tests.garbage.input"
        defer { Self.deleteKEK(service: service) }

        let garbage = (0..<Self.wrappedLength).map { UInt8($0 & 0xFF) }
        let result = Self.unwrap(garbage, service: service)
        #expect(result.status != 0)
    }

    // MARK: - hkdfguard_generate_and_wrap_dek

    @Test func generateAndWrapProducesAnUnwrappableDEK() {
        let service = "com.hkdfguard.tests.generate.and.wrap.roundtrip"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.generateAndWrap(service: service)
        #expect(result.status == 0)
        #expect(result.wrapped.count == Self.wrappedLength)

        let unwrapResult = Self.unwrap(result.wrapped, service: service)
        #expect(unwrapResult.status == 0)
        #expect(unwrapResult.plaintext.count == Self.dekLength)
    }

    @Test func twoGenerateAndWrapCallsProduceDifferentDEKs() {
        // Each call sources its own fresh CSPRNG randomness for the DEK
        // itself, not just a fresh nonce/ephemeral key - this is the check
        // that actually distinguishes "generates a new DEK" from "wraps a
        // fixed/reused buffer."
        let service = "com.hkdfguard.tests.generate.and.wrap.uniqueness"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let first = Self.generateAndWrap(service: service)
        let second = Self.generateAndWrap(service: service)
        #expect(first.status == 0)
        #expect(second.status == 0)

        let firstDEK = Self.unwrap(first.wrapped, service: service).plaintext
        let secondDEK = Self.unwrap(second.wrapped, service: service).plaintext
        #expect(firstDEK != secondDEK)
    }

    @Test func generateAndWrapRejectsEmptyServiceIdentifier() {
        // No defer/cleanup needed: an empty service is rejected before any
        // key provisioning or DEK generation happens.
        let result = Self.generateAndWrap(service: "")
        #expect(result.status == -8) // invalidServiceIdentifier
    }

    @Test func generateAndWrapReportsRequiredCapacityWhenBufferTooSmall() {
        let service = "com.hkdfguard.tests.generate.and.wrap.buffer.too.small"
        defer { Self.deleteKEK(service: service) }
        #expect(Self.createKEK(service: service) == 0)

        let result = Self.generateAndWrap(service: service, bufferCapacity: 10)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.wrappedLength))
    }
}
