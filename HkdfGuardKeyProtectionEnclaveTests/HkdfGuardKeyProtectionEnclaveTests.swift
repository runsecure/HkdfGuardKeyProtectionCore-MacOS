//
//  HkdfGuardKeyProtectionEnclaveTests.swift
//  HkdfGuardKeyProtectionEnclaveTests
//

import Testing
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
///   -3 = keyUnavailable, -6 = decryptionFailed.
struct HkdfGuardKeyProtectionEnclaveWrapUnwrapTests {

    // MARK: - Helpers

    private static let dekLength = 32
    private static let wrappedLength = 124 // 64-byte ephemeral pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag

    private static func randomDEK() -> [UInt8] {
        (0..<dekLength).map { _ in UInt8.random(in: .min ... .max) }
    }

    private static func wrap(
        _ dek: [UInt8],
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, wrapped: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = dek.withUnsafeBufferPointer { dekBuf in
            out.withUnsafeMutableBufferPointer { outBuf in
                hkdfguard_wrap_dek(
                    dekPtr: dekBuf.baseAddress!,
                    dekLen: Int32(dek.count),
                    outPtr: outBuf.baseAddress!,
                    outLen: &outLen
                )
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    private static func unwrap(
        _ wrapped: [UInt8],
        bufferCapacity: Int32 = 1024
    ) -> (status: Int32, plaintext: [UInt8], requiredLen: Int32) {
        var out = [UInt8](repeating: 0, count: Int(bufferCapacity))
        var outLen = bufferCapacity
        let status = wrapped.withUnsafeBufferPointer { wrappedBuf in
            out.withUnsafeMutableBufferPointer { outBuf in
                hkdfguard_unwrap_dek(
                    wrappedPtr: wrappedBuf.baseAddress!,
                    wrappedLen: Int32(wrapped.count),
                    outPtr: outBuf.baseAddress!,
                    outLen: &outLen
                )
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))), outLen)
    }

    // MARK: - Round trip

    @Test func wrapThenUnwrapRecoversOriginalDEK() {
        let dek = Self.randomDEK()

        let wrapResult = Self.wrap(dek)
        #expect(wrapResult.status == 0)

        let unwrapResult = Self.unwrap(wrapResult.wrapped)
        #expect(unwrapResult.status == 0)
        #expect(unwrapResult.plaintext == dek)
    }

    @Test func wrappedOutputHasExpectedLength() {
        let result = Self.wrap(Self.randomDEK())
        #expect(result.status == 0)
        #expect(result.wrapped.count == Self.wrappedLength)
    }

    @Test func twoWrapsOfSameDEKProduceDifferentCiphertext() {
        // Each wrap uses a fresh ephemeral key + random AES-GCM nonce, so
        // wrapping the same DEK twice must never produce identical output —
        // this is what makes the scheme semantically secure rather than
        // just "encrypted."
        let dek = Self.randomDEK()
        let first = Self.wrap(dek)
        let second = Self.wrap(dek)

        #expect(first.status == 0)
        #expect(second.status == 0)
        #expect(first.wrapped != second.wrapped)
    }

    // MARK: - Input validation

    @Test func wrapRejectsIncorrectDEKLength() {
        let tooShort = [UInt8](repeating: 0, count: 16)
        let result = Self.wrap(tooShort)
        #expect(result.status == -1) // invalidInputLength
    }

    @Test func unwrapRejectsBlobShorterThanEphemeralKey() {
        let tooShort = [UInt8](repeating: 0, count: 32)
        let result = Self.unwrap(tooShort)
        #expect(result.status == -1) // invalidInputLength
    }

    // MARK: - Output buffer sizing

    @Test func wrapReportsRequiredCapacityWhenBufferTooSmall() {
        let result = Self.wrap(Self.randomDEK(), bufferCapacity: 10)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.wrappedLength))
    }

    @Test func unwrapReportsRequiredCapacityWhenBufferTooSmall() {
        let wrapped = Self.wrap(Self.randomDEK()).wrapped
        let result = Self.unwrap(wrapped, bufferCapacity: 4)
        #expect(result.status == -2) // outputBufferTooSmall
        #expect(result.requiredLen == Int32(Self.dekLength))
    }

    // MARK: - Tamper detection

    @Test func unwrapRejectsTamperedCiphertext() {
        var wrapped = Self.wrap(Self.randomDEK()).wrapped
        // Flip a bit inside the AES-GCM ciphertext/tag region (well past
        // the 64-byte ephemeral public key prefix).
        wrapped[wrapped.count - 1] ^= 0xFF

        let result = Self.unwrap(wrapped)
        #expect(result.status == -6) // decryptionFailed — the GCM tag check must catch this
    }

    @Test func unwrapRejectsGarbageInput() {
        let garbage = (0..<Self.wrappedLength).map { UInt8($0 & 0xFF) }
        let result = Self.unwrap(garbage)
        #expect(result.status != 0)
    }
}
