import Foundation
import CryptoKit
import Security

#if compiler(<6.2)
#error("HkdfGuardKeyProtectionEnclave requires a Swift 6.2 or later toolchain.")
#endif

// MARK: - Configuration

/// Keychain account used alongside the caller-supplied service identifier
/// to persist the Secure Enclave key's opaque data representation. This is
/// *not* the key material itself — a
/// `SecureEnclave.P256.KeyAgreement.PrivateKey`'s `dataRepresentation` is an
/// encrypted blob that only this device's Secure Enclave can turn back into
/// a usable key; it cannot be used to recover the raw private key anywhere
/// else. The service identifier varies per calling application (passed in
/// from the C boundary); this account suffix stays fixed so each service's
/// keychain item differs only by that identifier.
let hkdfguardKeychainAccount = "kek-v1" // internal (not private) so @testable-import test code can clean up keychain items it creates

/// Expected length of the Data Encryption Key being wrapped/unwrapped.
private let hkdfguardDekLength = 32

/// Length, in bytes, of a P-256 public key's raw (x || y) representation.
private let hkdfguardEphemeralPublicKeyLength = 64

/// Context string binding the HKDF-derived key to this specific wrap
/// scheme, so it can never be reused as a key for anything else.
private let hkdfguardSharedInfo = Data("com.hkdfguard.macos.wrap.v1".utf8)

// MARK: - Status codes returned across the C boundary

private enum HKDFGuardStatus: Int32 {
    case success = 0
    case invalidInputLength = -1
    case outputBufferTooSmall = -2
    case keyUnavailable = -3
    case publicKeyUnavailable = -4
    case encryptionFailed = -5
    case decryptionFailed = -6
    case unexpectedOutputLength = -7
    case missingServiceIdentifier = -8
}

// MARK: - Secure Enclave KEK lookup / provisioning

/// Access control restricting the Secure Enclave key to this device, usable
/// only while the device is unlocked.
private func makeAccessControl() -> SecAccessControl? {
    var error: Unmanaged<CFError>?
    return SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        &error
    )
}

/// Looks up the persisted Secure Enclave key's opaque data representation
/// in the keychain, under the caller-supplied service identifier.
private func loadKEKDataRepresentation(service: String) -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: hkdfguardKeychainAccount,
        kSecReturnData as String: true
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else { return nil }
    return data
}

/// Persists the Secure Enclave key's opaque data representation in the
/// keychain, under the caller-supplied service identifier. Does not
/// overwrite an existing item — `SecItemAdd` enforces a unique index on
/// service+account, so if another caller has concurrently created one
/// first, this simply (and correctly) fails rather than clobbering it;
/// `getOrCreateKEK` below is what decides what to do next.
@discardableResult
private func storeKEKDataRepresentation(_ data: Data, service: String) -> Bool {
    let attributes: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: hkdfguardKeychainAccount,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    return SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess
}

/// Returns the persisted Secure Enclave KEK for the given service
/// identifier, creating and persisting one on first use. Each distinct
/// `service` string gets its own independent key, isolated from every
/// other service's. The private key material never leaves the Secure
/// Enclave; only an opaque, device-bound data representation is stored,
/// and only that device's Secure Enclave can turn it back into a usable
/// key.
///
/// This is safe under concurrent first-use (e.g. parallel test execution
/// calling this before any KEK exists): if two callers both miss the load
/// below and both generate a new SE key, `SecItemAdd`'s unique index on
/// service+account lets only one of them actually persist theirs — the
/// loser doesn't treat that as failure, it re-reads and converges on the
/// winner's key instead. Without this, a concurrent first-use would
/// non-deterministically report `keyUnavailable` for the losing callers.
private func getOrCreateKEK(service: String) -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
    if let existing = loadKEKDataRepresentation(service: service),
       let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: existing) {
        return key
    }

    guard SecureEnclave.isAvailable,
          let access = makeAccessControl(),
          let newKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) else {
        return nil
    }

    if storeKEKDataRepresentation(newKey.dataRepresentation, service: service) {
        return newKey
    }

    if let existing = loadKEKDataRepresentation(service: service),
       let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: existing) {
        return key
    }

    return nil
}

/// Derives the AES-256 key used to seal/open the DEK from an ECDH shared
/// secret. The ephemeral public key doubles as the HKDF salt, binding the
/// derived key to this specific exchange.
private func deriveWrappingKey(sharedSecret: SharedSecret, ephemeralPublicKeyRaw: Data) -> SymmetricKey {
    sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeralPublicKeyRaw,
        sharedInfo: hkdfguardSharedInfo,
        outputByteCount: 32
    )
}

// MARK: - Wrap (encrypt) a DEK under the Secure Enclave KEK
//
// Wrapped format: [ephemeral P-256 public key, 64 bytes raw (x || y)]
//                  [AES-GCM combined: 12-byte nonce || ciphertext || 16-byte tag]
//
// This is a manual ECIES construction — ephemeral ECDH (with the Secure
// Enclave doing the enclave-side scalar multiplication) + HKDF-SHA256 +
// AES-GCM — replacing the earlier Security.framework
// `SecKeyCreateEncryptedData`/`CFData` based approach with CryptoKit's
// native Secure Enclave key-agreement API.

@_cdecl("hkdfguard_wrap_dek")
public func hkdfguard_wrap_dek(
    servicePtr: UnsafePointer<CChar>,
    dekPtr: UnsafePointer<UInt8>,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    guard dekLen == Int32(hkdfguardDekLength) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    let service = String(cString: servicePtr)
    guard !service.isEmpty else {
        return HKDFGuardStatus.missingServiceIdentifier.rawValue
    }

    // enclaveKey, ephemeralPrivateKey, sharedSecret, and wrappingKey are
    // all confined to this block: each is key material of one form or
    // another, and this scope ends — releasing all of them — the moment
    // `seal` returns, well before the capacity check / memcpy below run.
    // Relying on ARC's lexical-scope-end release here (rather than the
    // optimizer's last-use shrinking, which is not guaranteed, especially
    // across calls into an opaque framework like CryptoKit) is what
    // actually pins down *when* they go away.
    let ephemeralPublicRaw: Data
    let sealedBox: AES.GCM.SealedBox
    do {
        guard let enclaveKey = getOrCreateKEK(service: service) else {
            return HKDFGuardStatus.keyUnavailable.rawValue
        }

        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        ephemeralPublicRaw = ephemeralPrivateKey.publicKey.rawRepresentation

        guard let sharedSecret = try? ephemeralPrivateKey.sharedSecretFromKeyAgreement(
            with: enclaveKey.publicKey
        ) else {
            return HKDFGuardStatus.encryptionFailed.rawValue
        }

        let wrappingKey = deriveWrappingKey(sharedSecret: sharedSecret, ephemeralPublicKeyRaw: ephemeralPublicRaw)

        // Seal directly from the caller's buffer — CryptoKit accepts any
        // `DataProtocol` source, including a raw pointer, so the
        // plaintext DEK is never staged in a Swift-owned copy on this
        // side at all.
        do {
            sealedBox = try AES.GCM.seal(UnsafeRawBufferPointer(start: dekPtr, count: Int(dekLen)), using: wrappingKey)
        } catch {
            return HKDFGuardStatus.encryptionFailed.rawValue
        }
    }

    guard let combined = sealedBox.combined else {
        return HKDFGuardStatus.encryptionFailed.rawValue
    }

    let totalLen = ephemeralPublicRaw.count + combined.count
    let capacity = Int(outLen.pointee)
    guard capacity >= totalLen else {
        outLen.pointee = Int32(totalLen)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    _ = ephemeralPublicRaw.withUnsafeBytes { raw in
        memcpy(outPtr, raw.baseAddress!, ephemeralPublicRaw.count)
    }
    _ = combined.withUnsafeBytes { raw in
        memcpy(outPtr + ephemeralPublicRaw.count, raw.baseAddress!, combined.count)
    }
    outLen.pointee = Int32(totalLen)

    return HKDFGuardStatus.success.rawValue
}

// MARK: - Unwrap (decrypt) a DEK using the Secure Enclave KEK

@_cdecl("hkdfguard_unwrap_dek")
public func hkdfguard_unwrap_dek(
    servicePtr: UnsafePointer<CChar>,
    wrappedPtr: UnsafePointer<UInt8>,
    wrappedLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    guard wrappedLen > Int32(hkdfguardEphemeralPublicKeyLength) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    let service = String(cString: servicePtr)
    guard !service.isEmpty else {
        return HKDFGuardStatus.missingServiceIdentifier.rawValue
    }

    let ephemeralPublicRaw = Data(bytes: wrappedPtr, count: hkdfguardEphemeralPublicKeyLength)
    let combined = Data(
        bytes: wrappedPtr + hkdfguardEphemeralPublicKeyLength,
        count: Int(wrappedLen) - hkdfguardEphemeralPublicKeyLength
    )

    guard let ephemeralPublicKey = try? P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicRaw) else {
        return HKDFGuardStatus.decryptionFailed.rawValue
    }
    guard let sealedBox = try? AES.GCM.SealedBox(combined: combined) else {
        return HKDFGuardStatus.decryptionFailed.rawValue
    }

    // `plaintext` is declared here (once, as the sole binding — never
    // aliased into a second variable) but only *assigned* inside the
    // nested block below, so `enclaveKey`/`sharedSecret`/`wrappingKey`
    // are confined to that block and released the moment `open` returns,
    // before the length/capacity checks and memcpy that follow run.
    var plaintext: Data
    do {
        guard let enclaveKey = getOrCreateKEK(service: service) else {
            return HKDFGuardStatus.keyUnavailable.rawValue
        }
        guard let sharedSecret = try? enclaveKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey) else {
            return HKDFGuardStatus.decryptionFailed.rawValue
        }
        let wrappingKey = deriveWrappingKey(sharedSecret: sharedSecret, ephemeralPublicKeyRaw: ephemeralPublicRaw)
        do {
            plaintext = try AES.GCM.open(sealedBox, using: wrappingKey)
        } catch {
            return HKDFGuardStatus.decryptionFailed.rawValue
        }
    }

    // `Data.withUnsafeMutableBytes` is a safe, sanctioned way to scrub a
    // `Data`'s own storage in place (unlike force-casting a CFData to a
    // mutable type), and `defer` guarantees it runs on every exit path
    // below, not just the success path.
    defer {
        _ = plaintext.withUnsafeMutableBytes { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }

    guard plaintext.count == hkdfguardDekLength else {
        return HKDFGuardStatus.unexpectedOutputLength.rawValue
    }

    let capacity = Int(outLen.pointee)
    guard capacity >= plaintext.count else {
        outLen.pointee = Int32(plaintext.count)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    _ = plaintext.withUnsafeBytes { raw in
        memcpy(outPtr, raw.baseAddress!, plaintext.count)
    }
    outLen.pointee = Int32(plaintext.count)

    return HKDFGuardStatus.success.rawValue
}
