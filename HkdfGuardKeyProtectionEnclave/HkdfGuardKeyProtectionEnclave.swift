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

/// Length, in bytes, of the SHA-256 "fingerprint" embedded at the front of
/// every wrapped payload — see `kekFingerprint` below.
private let hkdfguardFingerprintLength = 32

/// Context string binding the HKDF-derived key to this specific wrap
/// scheme, so it can never be reused as a key for anything else.
private let hkdfguardSharedInfo = Data("com.hkdfguard.macos.wrap.v1".utf8)

// MARK: - Status codes returned across the C boundary

private enum HKDFGuardStatus: Int32 {
    case success = 0
    case invalidInputLength = -1
    case outputBufferTooSmall = -2
    /// Reserved but no longer returned by anything below — every path that
    /// used to collapse into this now has its own, more specific code at
    /// -10 or below (see `kekNotFound`, `kekCorrupted`,
    /// `accessControlCreationFailed`, `keyGenerationFailed`,
    /// `keychainWriteFailed`, `kekVerificationFailed`). Kept defined,
    /// rather than deleted, so the numeric value -3 stays reserved and a
    /// caller pattern-matching on it doesn't silently start matching
    /// something unrelated.
    case keyUnavailable = -3
    case publicKeyUnavailable = -4
    case encryptionFailed = -5
    case decryptionFailed = -6
    case unexpectedOutputLength = -7
    case invalidServiceIdentifier = -8
    case enclaveUnavailable = -9

    // MARK: KEK-lifecycle failures — each a distinct reason that used to
    // collapse into the single `keyUnavailable` (-3) above. Split out so a
    // caller can actually tell "no key yet" (ordinary, often not even an
    // error) apart from "the Secure Enclave/keychain refused to cooperate"
    // (worth surfacing/logging) apart from "this looks like a bug in this
    // library" (worth reporting).

    /// No keychain item exists yet for this service — the ordinary,
    /// expected state before the first `hkdfguard_create_kek` call for a
    /// given service, surfaced by `hkdfguard_wrap_dek`/
    /// `hkdfguard_unwrap_dek` now that they no longer create one
    /// implicitly.
    case kekNotFound = -10

    /// A keychain item exists under this service, but its stored data
    /// representation could not be reconstructed into a usable Secure
    /// Enclave key — a corrupt or foreign entry. Deliberately never
    /// "healed" by generating a replacement: that would silently orphan
    /// whatever the original key protected.
    case kekCorrupted = -11

    /// `SecAccessControlCreateWithFlags` failed while provisioning a new
    /// KEK, before any Secure Enclave key was even requested.
    case accessControlCreationFailed = -12

    /// The Secure Enclave refused to generate a new P-256 key-agreement
    /// key for this service (distinct from the enclave being entirely
    /// unavailable, which is `enclaveUnavailable` above).
    case keyGenerationFailed = -13

    /// `SecItemAdd` failed while persisting a newly generated KEK, with an
    /// `OSStatus` other than success or "another caller already won the
    /// race" (`errSecDuplicateItem`, which is not an error — see
    /// `createKEK`'s handling of it).
    case keychainWriteFailed = -14

    /// A KEK was just generated and successfully stored, but immediately
    /// reloading and reconstructing it afterward — the verification step
    /// that confirms what's now persisted is actually usable — failed.
    /// Should not happen in practice; kept distinct rather than folded
    /// into `kekCorrupted` because it points at a different moment
    /// (verification of a write this process just made, not a
    /// pre-existing item found on lookup).
    case kekVerificationFailed = -15

    /// The wrapped payload's embedded KEK fingerprint (see
    /// `kekFingerprint` below) doesn't match the public key of the KEK
    /// this service currently resolves to — this payload was not wrapped
    /// under the key `hkdfguard_unwrap_dek` is about to use. Detected and
    /// returned before any ECDH/AES-GCM decryption is attempted, not
    /// derived from one: unlike `decryptionFailed`, this specifically
    /// means "wrong KEK," not "right KEK, but tampered/mismatched data."
    case fingerprintMismatch = -16
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

/// Every C ABI entry point below calls this immediately after converting
/// the raw C string, before validation or any keychain/crypto use —
/// service names are case-insensitive (`"Com.Example.App"` and
/// `"com.example.app"` must resolve to the same KEK), so lowercasing here,
/// once, up front, is what makes that true everywhere downstream:
/// `validServiceName`, the keychain query/store calls, and the
/// AES-GCM/HKDF `service` bytes all only ever see this normalized form.
/// Lowercasing is charset-safe for this purpose — `validServiceName`
/// only accepts ASCII letters, digits, and '.', none of which change
/// length or collide with one another under ASCII case-folding.
private func normalizedService(from servicePtr: UnsafePointer<CChar>) -> String {
    String(cString: servicePtr).lowercased()
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

/// Reports whether a valid, reconstructable KEK already exists for
/// `service`, without creating one. Distinguishes "no key yet" (`success`,
/// `false`) from "a keychain item is present but can't be reconstructed"
/// (`kekCorrupted`, `false`) — a caller that only looked at the boolean
/// would otherwise treat a corrupt/foreign entry the same as a clean slate.
private func kekExists(service: String) -> (status: Int32, exists: Bool) {
    guard validServiceName(service: service) else {
        return (HKDFGuardStatus.invalidServiceIdentifier.rawValue, false)
    }

    guard SecureEnclave.isAvailable else {
        return (HKDFGuardStatus.enclaveUnavailable.rawValue, false)
    }

    guard let existing = loadKEKDataRepresentation(service: service) else {
        return (HKDFGuardStatus.success.rawValue, false)
    }

    guard let _ = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: existing) else {
        return (HKDFGuardStatus.kekCorrupted.rawValue, false)
    }

    return (HKDFGuardStatus.success.rawValue, true)
}

/// Creates a KEK for `service` if one doesn't already exist. Idempotent
/// and safe under concurrent first-use — see the duplicate-item handling
/// below — so a caller that already checked `kekExists` and got `false`
/// doesn't need to treat a race against another creator as its own error.
private func createKEK(service: String) -> Int32 {

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
            return HKDFGuardStatus.kekCorrupted.rawValue
        }

        return HKDFGuardStatus.success.rawValue
    }

    // No key exists. Create one.
    guard let access = makeAccessControl() else {
        return HKDFGuardStatus.accessControlCreationFailed.rawValue
    }

    guard let newKey =
        try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access
        )
    else {
        return HKDFGuardStatus.keyGenerationFailed.rawValue
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
            return HKDFGuardStatus.kekVerificationFailed.rawValue
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
            return HKDFGuardStatus.kekCorrupted.rawValue
        }

        return HKDFGuardStatus.success.rawValue

    default:
        return HKDFGuardStatus.keychainWriteFailed.rawValue
    }
}

/// Looks up the KEK for `service` — never creates one. Returns the
/// specific reason it couldn't, when it couldn't, rather than a plain
/// `nil`: `wrapDekCore`/`hkdfguard_unwrap_dek` below propagate this
/// `status` directly on failure, so a caller finds out whether there's
/// simply no key yet (`kekNotFound` — the ordinary state before
/// `hkdfguard_create_kek` has been called), the enclave itself is
/// unavailable, the service name is malformed, or an existing item is
/// corrupt, instead of one indistinguishable `keyUnavailable`.
private func getKEK(service: String) -> (status: Int32, key: SecureEnclave.P256.KeyAgreement.PrivateKey?) {
    guard validServiceName(service: service) else {
        return (HKDFGuardStatus.invalidServiceIdentifier.rawValue, nil)
    }

    guard SecureEnclave.isAvailable else {
        return (HKDFGuardStatus.enclaveUnavailable.rawValue, nil)
    }

    guard let existing = loadKEKDataRepresentation(service: service) else {
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    }

    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: existing) else {
        return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
    }

    return (HKDFGuardStatus.success.rawValue, key)
}

/// Computes the "fingerprint" embedded at the front of every wrapped
/// payload: a SHA-256 hash of the KEK's public key raw representation.
/// Not a secret value — the public key it hashes isn't secret either —
/// so the explicit equality check against it in `hkdfguard_unwrap_dek`
/// exists purely to fail fast, cheaply, on "this payload wasn't wrapped
/// under the KEK I just resolved for this service" *before* spending any
/// effort on ECDH/AES-GCM. It is also folded into the AES-GCM AAD (see
/// `wrapDekCore`/`hkdfguard_unwrap_dek`) alongside `service`, so the tag
/// itself authenticates it too.
private func kekFingerprint(publicKeyRaw: Data) -> Data {
    Data(SHA256.hash(data: publicKeyRaw))
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
// Wrapped format: [KEK fingerprint, 32-byte SHA-256 of the KEK's public key]
//                  [ephemeral P-256 public key, 64 bytes raw (x || y)]
//                  [AES-GCM combined: 12-byte nonce || ciphertext || 16-byte tag]
//
// The fingerprint identifies *which* KEK this payload was wrapped under —
// checked against the current KEK's own public key by
// hkdfguard_unwrap_dek before any ECDH/AES-GCM is attempted (see
// `kekFingerprint`), and it is also folded into the AES-GCM AAD alongside
// the service string, so the tag itself covers it too: tampering with the
// fingerprint bytes fails both the explicit pre-check and, independently,
// AES-GCM authentication.

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

    let fingerprint: Data
    let ephemeralPublicRaw: Data
    let sealedBox: AES.GCM.SealedBox
    do {
        let (getStatus, maybeEnclaveKey) = getKEK(service: service)
        guard let enclaveKey = maybeEnclaveKey else {
            return getStatus
        }

        fingerprint = kekFingerprint(publicKeyRaw: enclaveKey.publicKey.rawRepresentation)

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

        // The fingerprint is bound into the AES-GCM AAD alongside the
        // service string, so tampering with the fingerprint bytes in the
        // wrapped payload breaks the GCM tag too, not just the explicit
        // equality check in hkdfguard_unwrap_dek.
        var aad = Data(service.utf8)
        aad.append(fingerprint)

        do {
            sealedBox = try AES.GCM.seal(
                UnsafeRawBufferPointer(start: dekPtr, count: Int(dekLen)),
                using: wrappingKey,
                authenticating: aad
            )
        } catch {
            return HKDFGuardStatus.encryptionFailed.rawValue
        }
    }

    guard let combined = sealedBox.combined else {
        return HKDFGuardStatus.encryptionFailed.rawValue
    }

    let totalLen = fingerprint.count + ephemeralPublicRaw.count + combined.count
    let capacity = Int(outLen.pointee)
    guard capacity >= totalLen else {
        outLen.pointee = Int32(totalLen)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    _ = fingerprint.withUnsafeBytes { raw in
        memcpy(outPtr, raw.baseAddress!, fingerprint.count)
    }
    _ = ephemeralPublicRaw.withUnsafeBytes { raw in
        memcpy(outPtr + fingerprint.count, raw.baseAddress!, ephemeralPublicRaw.count)
    }
    _ = combined.withUnsafeBytes { raw in
        memcpy(outPtr + fingerprint.count + ephemeralPublicRaw.count, raw.baseAddress!, combined.count)
    }
    outLen.pointee = Int32(totalLen)

    return HKDFGuardStatus.success.rawValue
}

/// Reports whether a Secure Enclave KEK already exists for `service`,
/// without creating one — `*outExists` is always written, on every return
/// path (1 if a valid KEK exists, 0 otherwise, including when the status
/// isn't `success`, in which case existence couldn't be determined), so
/// the caller's variable is never left in an undefined state.
@_cdecl("hkdfguard_kek_exists")
public func hkdfguard_kek_exists(
    servicePtr: UnsafePointer<CChar>,
    outExists: UnsafeMutablePointer<Int32>
) -> Int32 {
    outExists.pointee = 0

    let service = normalizedService(from: servicePtr)

    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let (status, exists) = kekExists(service: service)
    outExists.pointee = exists ? 1 : 0
    return status
}

/// Creates a Secure Enclave KEK for `service` if one doesn't already
/// exist. Paired with `hkdfguard_kek_exists` above so a caller can decide
/// for itself whether creation is needed — e.g. prompting for user
/// consent, or provisioning on a schedule — rather than have that decision
/// made implicitly inside a single combined "ensure" call.
@_cdecl("hkdfguard_create_kek")
public func hkdfguard_create_kek(
    servicePtr: UnsafePointer<CChar>
) -> Int32 {
    let service = normalizedService(from: servicePtr)

    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    return createKEK(service: service)
}

@_cdecl("hkdfguard_wrap_dek")
public func hkdfguard_wrap_dek(
    servicePtr: UnsafePointer<CChar>,
    dekPtr: UnsafePointer<UInt8>,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>,
    outLen: UnsafeMutablePointer<Int32>
) -> Int32 {
    let service = normalizedService(from: servicePtr)
    
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
    let service = normalizedService(from: servicePtr)

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
    let fixedPrefixLength = hkdfguardFingerprintLength + hkdfguardEphemeralPublicKeyLength
    guard wrappedLen > Int32(fixedPrefixLength) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    let service = normalizedService(from: servicePtr)

    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let storedFingerprint = Data(bytes: wrappedPtr, count: hkdfguardFingerprintLength)
    let ephemeralPublicRaw = Data(bytes: wrappedPtr + hkdfguardFingerprintLength, count: hkdfguardEphemeralPublicKeyLength)
    let combined = Data(
        bytes: wrappedPtr + fixedPrefixLength,
        count: Int(wrappedLen) - fixedPrefixLength
    )

    var plaintext: Data
    do {
        let (getStatus, maybeEnclaveKey) = getKEK(service: service)
        guard let enclaveKey = maybeEnclaveKey else {
            return getStatus
        }

        // Checked against the *current* KEK's own public key before any
        // ECDH/AES-GCM is attempted below — a plain equality comparison
        // is fine here since neither side is secret (both are public-key
        // material); this is a fast, specific "wrong/stale KEK" signal
        // that fails fast, ahead of the AES-GCM tag check below, which
        // also covers this same fingerprint (see the AAD construction
        // further down) and would catch a tampered fingerprint anyway.
        let currentFingerprint = kekFingerprint(publicKeyRaw: enclaveKey.publicKey.rawRepresentation)
        guard currentFingerprint == storedFingerprint else {
            return HKDFGuardStatus.fingerprintMismatch.rawValue
        }

        guard let ephemeralPublicKey = try? P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicRaw) else {
            return HKDFGuardStatus.decryptionFailed.rawValue
        }
        guard let sealedBox = try? AES.GCM.SealedBox(combined: combined) else {
            return HKDFGuardStatus.decryptionFailed.rawValue
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

        // Must exactly mirror the AAD constructed in wrapDekCore.
        // currentFingerprint == storedFingerprint is already guaranteed by
        // the guard above, so either would do here — currentFingerprint is
        // used since it's the value this call site just computed.
        var aad = Data(service.utf8)
        aad.append(currentFingerprint)

        do {
            plaintext = try AES.GCM.open(sealedBox, using: wrappingKey, authenticating: aad)
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
