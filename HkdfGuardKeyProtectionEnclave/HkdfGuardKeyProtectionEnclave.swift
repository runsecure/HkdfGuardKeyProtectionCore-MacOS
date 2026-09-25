import Foundation
import CryptoKit
import Security

#if compiler(<6.2)
#error("HkdfGuardKeyProtectionEnclave requires a Swift 6.2 or later toolchain.")
#endif

// MARK: - Configuration

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
    case invalidServiceIdentifier = -8
    case enclaveUnavailable = -9
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

private func isValidServiceChar(c: Character) -> Bool {
    return c.isLetter || c.isNumber || c == "."
}

private func validServiceName(service: String) -> Bool {
    guard !service.isEmpty else {
        return false
    }
    
    guard service.count <= 128 else {
        return false
    }
    
    for c in service {
        if !isValidServiceChar(c: c) {
            return false
        }
    }
    
    return true
}

/// Looks up the persisted Secure Enclave key's opaque data representation
/// in the keychain, under the caller-supplied service identifier.
private func loadKEKDataRepresentation(service: String) -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: hkdfguardKeychainAccount,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else { return nil }
    return data
}

@discardableResult
private func storeKEKDataRepresentation(_ data: Data, service: String) -> OSStatus {
    let attributes: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: hkdfguardKeychainAccount,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    return SecItemAdd(attributes as CFDictionary, nil)
}

private func ensureKEK(service: String) -> Int32 {

    // Validate service identifier.
    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    // Secure Enclave must exist.
    guard SecureEnclave.isAvailable else {
        return HKDFGuardStatus.enclaveUnavailable.rawValue
    }

    // Existing key?
    if let existing = loadKEKDataRepresentation(service: service) {

        guard let _ =
            try? SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: existing
            )
        else {
            // Item exists but cannot be reconstructed.
            // Do NOT generate a replacement key.
            return HKDFGuardStatus.keyUnavailable.rawValue
        }

        return HKDFGuardStatus.success.rawValue
    }

    // No key exists. Create one.
    guard let access = makeAccessControl() else {
        return HKDFGuardStatus.keyUnavailable.rawValue
    }

    guard let newKey =
        try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access
        )
    else {
        return HKDFGuardStatus.keyUnavailable.rawValue
    }

    let status = storeKEKDataRepresentation(
        newKey.dataRepresentation,
        service: service
    )

    switch status {

    case errSecSuccess:

        // Verify store/reload/reconstruct succeeds.
        guard
            let stored =
                loadKEKDataRepresentation(service: service),
            let _ =
                try? SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: stored
                )
        else {
            return HKDFGuardStatus.keyUnavailable.rawValue
        }

        return HKDFGuardStatus.success.rawValue

    case errSecDuplicateItem:

        // Another thread/process won the race.
        // Validate the winner's key before declaring success.
        guard
            let existing =
                loadKEKDataRepresentation(service: service),
            let _ =
                try? SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: existing
                )
        else {
            return HKDFGuardStatus.keyUnavailable.rawValue
        }

        return HKDFGuardStatus.success.rawValue

    default:
        return HKDFGuardStatus.keyUnavailable.rawValue
    }
}

private func getKEK(service: String) -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
    guard validServiceName(service: service) else {
        return nil
    }
    
    guard SecureEnclave.isAvailable else {
        return nil
    }
    
    guard
        let existing =
            loadKEKDataRepresentation(service: service),
        let key =
            try? SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: existing
            ) else {
        return nil
    }

    return key
}

/// Derives the AES-256 key used to seal/open the DEK from an ECDH shared
/// secret. The ephemeral public key doubles as the HKDF salt, binding the
/// derived key to this specific exchange.
private func deriveWrappingKey(
    sharedSecret: SharedSecret,
    service: String,
    ephemeralPublicKeyRaw: Data,
    recipientPublicKeyRaw: Data
) -> SymmetricKey {

    var sharedInfo = Data()

    sharedInfo.append(hkdfguardSharedInfo)

    sharedInfo.append(ephemeralPublicKeyRaw)

    sharedInfo.append(recipientPublicKeyRaw)

    sharedInfo.append(Data(service.utf8))

    return sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA512.self,
        salt: ephemeralPublicKeyRaw,
        sharedInfo: sharedInfo,
        outputByteCount: 32
    )
}

// MARK: - Wrap (encrypt) a DEK under the Secure Enclave KEK
//
// Wrapped format: [ephemeral P-256 public key, 64 bytes raw (x || y)]
//                  [AES-GCM combined: 12-byte nonce || ciphertext || 16-byte tag]

/// `@_cdecl` entry points below.
private func wrapDekCore(
    service: String,
    dekPtr: UnsafePointer<UInt8>,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    guard dekLen == Int32(hkdfguardDekLength) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    let ephemeralPublicRaw: Data
    let sealedBox: AES.GCM.SealedBox
    do {
        guard let enclaveKey = getKEK(service: service) else {
            return HKDFGuardStatus.keyUnavailable.rawValue
        }

        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        ephemeralPublicRaw = ephemeralPrivateKey.publicKey.rawRepresentation

        guard let sharedSecret = try? ephemeralPrivateKey.sharedSecretFromKeyAgreement(
            with: enclaveKey.publicKey
        ) else {
            return HKDFGuardStatus.encryptionFailed.rawValue
        }

        let wrappingKey = deriveWrappingKey(
            sharedSecret: sharedSecret,
            service: service,
            ephemeralPublicKeyRaw: ephemeralPublicRaw,
            recipientPublicKeyRaw: enclaveKey.publicKey.rawRepresentation
        )

        do {
            sealedBox = try AES.GCM.seal(
                UnsafeRawBufferPointer(start: dekPtr, count: Int(dekLen)),
                using: wrappingKey,
                authenticating: Data(service.utf8)
            )
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

@_cdecl("hkdfguard_ensure_kek")
public func hkdfguard_ensure_kek(
    servicePtr: UnsafePointer<CChar>
) -> Int32 {
    let service = String(cString: servicePtr)
    
    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }
    
    return ensureKEK(service: service)
}

@_cdecl("hkdfguard_wrap_dek")
public func hkdfguard_wrap_dek(
    servicePtr: UnsafePointer<CChar>,
    dekPtr: UnsafePointer<UInt8>,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    let service = String(cString: servicePtr)
    
    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }
    
    return wrapDekCore(service: service, dekPtr: dekPtr, dekLen: dekLen, outPtr: outPtr, outLen: outLen)
}

// MARK: - Generate a new random DEK and wrap it, in one call

private func generateRandomDek() -> Data? {
    var bytes = Data(count: hkdfguardDekLength)
    let status = bytes.withUnsafeMutableBytes { raw in
        SecRandomCopyBytes(kSecRandomDefault, hkdfguardDekLength, raw.baseAddress!)
    }
    guard status == errSecSuccess else { return nil }
    return bytes
}

@_cdecl("hkdfguard_generate_and_wrap_dek")
public func hkdfguard_generate_and_wrap_dek(
    servicePtr: UnsafePointer<CChar>,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    let service = String(cString: servicePtr)

    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }
    
    guard var dek = generateRandomDek() else {
        return HKDFGuardStatus.encryptionFailed.rawValue
    }

    defer {
        _ = dek.withUnsafeMutableBytes { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }

    return dek.withUnsafeBytes { raw -> Int32 in
        wrapDekCore(
            service: service,
            dekPtr: raw.bindMemory(to: UInt8.self).baseAddress!,
            dekLen: Int32(dek.count),
            outPtr: outPtr,
            outLen: outLen
        )
    }
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
    
    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
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

    var plaintext: Data
    do {
        guard let enclaveKey = getKEK(service: service) else {
            return HKDFGuardStatus.keyUnavailable.rawValue
        }
        guard let sharedSecret = try? enclaveKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey) else {
            return HKDFGuardStatus.decryptionFailed.rawValue
        }
        
        let wrappingKey = deriveWrappingKey(
            sharedSecret: sharedSecret,
            service: service,
            ephemeralPublicKeyRaw: ephemeralPublicRaw,
            recipientPublicKeyRaw: enclaveKey.publicKey.rawRepresentation
        )

        do {
            plaintext = try AES.GCM.open(sealedBox, using: wrappingKey, authenticating: Data(service.utf8))
        } catch {
            return HKDFGuardStatus.decryptionFailed.rawValue
        }
    }

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
