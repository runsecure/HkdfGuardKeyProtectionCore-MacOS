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

/// AES-GCM nonce and tag lengths, as fixed by CryptoKit's `AES.GCM`.
private let hkdfguardGCMNonceLength = 12
private let hkdfguardGCMTagLength = 16

/// The exact length of every wrapped payload: fingerprint || ephemeral
/// public key || nonce || ciphertext (same length as the DEK) || tag.
/// Known up front, so both wrap and unwrap can reject a wrong-sized buffer
/// before any keychain or Secure Enclave work.
private let hkdfguardWrappedLength =
    hkdfguardFingerprintLength + hkdfguardEphemeralPublicKeyLength
    + hkdfguardGCMNonceLength + hkdfguardDekLength + hkdfguardGCMTagLength

/// Context string binding the HKDF-derived key to this specific wrap
/// scheme, so it can never be reused as a key for anything else.
private let hkdfguardSharedInfo = Data("com.hkdfguard.macos.wrap.v1".utf8)

// MARK: - Keychain mode (hybrid)

/// Which keychain the KEK's keychain item lives in. Decided once per
/// process, from the process's own code-signing entitlements — see
/// `detectKeychainMode` — never from configuration or the environment.
///
/// - `dataProtection`: the process carries a `keychain-access-groups`
///   entitlement (which on macOS requires a Team-signed app bundle with an
///   embedded provisioning profile). Items go in the data-protection
///   keychain under `accessGroup`, where access is decided by securityd
///   from the caller's signed identity: no ACL prompts, no per-item ACLs,
///   `kSecAttrAccessible` is honored, and any Team-signed bundle listing
///   the same group shares the item deterministically. The hardened mode.
/// - `legacy`: no such entitlement (a bare executable: this CLI as a
///   plain Mach-O, a .NET/Python/Go host that `dlopen`s this dylib, the
///   `xctest` agent). Items go in the login keychain, protected by its
///   lock and a per-item ACL keyed to the creating binary's signature;
///   other identities hit an interactive prompt, or headless,
///   `keychainAccessDenied`.
///
/// This is not a silent downgrade: an unentitled process cannot see
/// data-protection items at all, and the mode is derived from a signature
/// an attacker cannot alter without invalidating it. It does create one
/// deployment invariant — **the process that provisions a service's KEK and
/// every process that unwraps under it must run in the same mode** — which
/// is why `hkdfguard_keychain_mode` exposes the decision and the CLI prints
/// it.
enum KeychainMode: Equatable {
    case legacy
    case dataProtection(accessGroup: String)
}

let hkdfguardKeychainMode: KeychainMode = detectKeychainMode()

private func detectKeychainMode() -> KeychainMode {
    guard let task = SecTaskCreateFromSelf(nil) else {
        return .legacy
    }
    guard let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
          let groups = value as? [String],
          let first = groups.first(where: { !$0.isEmpty }) else {
        return .legacy
    }
    return .dataProtection(accessGroup: first)
}

/// The attributes every keychain query/add for a service's KEK item shares,
/// including the ones that select the keychain `mode` puts it in.
private func keychainItemAttributes(service: String, mode: KeychainMode) -> [String: Any] {
    var attributes: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: hkdfguardKeychainAccount,
        // Explicit in both modes so a query can never match an iCloud-synced
        // item, and so the intent is visible rather than a default.
        kSecAttrSynchronizable as String: false,
    ]
    switch mode {
    case .legacy:
        // Explicit false, not omitted: on newer SDKs an omitted key can
        // default to the data-protection keychain rather than the legacy
        // file-based one for a process that also carries
        // keychain-access-groups, which would silently defeat the two
        // keychains' disjointness.
        attributes[kSecUseDataProtectionKeychain as String] = false
    case .dataProtection(let accessGroup):
        attributes[kSecUseDataProtectionKeychain as String] = true
        attributes[kSecAttrAccessGroup as String] = accessGroup
    }
    return attributes
}

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

    /// The keychain refused to say whether an item exists for this
    /// service: the keychain is locked or there is no UI session to
    /// prompt in (`errSecInteractionNotAllowed` — the headless-daemon
    /// case), the item's ACL denied this process or the user declined the
    /// access prompt (`errSecAuthFailed`, `errSecUserCanceled`), or this
    /// process lacks a required entitlement (`errSecMissingEntitlement`).
    /// Deliberately distinct from `kekNotFound`/`kekCorrupted`: a key very
    /// likely *does* exist, and treating this as "no key" or "corrupt key"
    /// would invite a caller to create a replacement or an operator to
    /// delete a healthy one.
    case keychainAccessDenied = -17

    /// `SecItemCopyMatching` failed with an `OSStatus` other than
    /// not-found or one of the access-denial codes above — e.g. no
    /// keychain available at all, or an unexpected item shape.
    case keychainReadFailed = -18
}

// MARK: - Secure Enclave KEK lookup / provisioning

/// The access policy baked into every KEK at creation — what the Secure
/// Enclave enforces on each use of the key, independent of which keychain
/// (see `KeychainMode`) the key's item lives in. Fixed; there is no
/// per-service override.
///
/// - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: usable only while the
///   device is unlocked, and never migrated to another device (no backup or
///   restore can carry it). "Unlocked" means the login user's keybag: a
///   LaunchDaemon or SSH session on a Mac with no unlocked GUI session may
///   find the key unavailable — surfacing as `keyGenerationFailed`/
///   `decryptionFailed` from the enclave, or `keychainAccessDenied` from a
///   locked keychain. Headless consumers should run as a LaunchAgent inside
///   a logged-in session, or otherwise ensure the login keychain is
///   unlocked.
/// - `.privateKeyUsage` alone — no `.userPresence`/`.biometryAny`, so no
///   Touch ID or password prompt is ever required to *use* the key. That is
///   deliberate: this library serves unattended services. It means the
///   protection boundary is "which processes may read the keychain item"
///   (the keychain mode's job), not "a human approved this use".
private func makeAccessControl() -> SecAccessControl? {
    var error: Unmanaged<CFError>?
    return SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        &error
    )
}

/// Maximum accepted length of a service name, in UTF-8 bytes (which, for
/// the ASCII-only charset below, is also its character count).
private let hkdfguardMaxServiceLength = 128

/// ASCII letters, digits, and '.' — nothing else. Checked on raw UTF-8
/// bytes rather than `Character` properties on purpose: `Character.isLetter`
/// / `isNumber` are Unicode-aware and would accept `é`, CJK, Arabic-Indic
/// digits, `½`, and so on, while `String.count` counts grapheme clusters
/// rather than bytes. The C header, the CLI, and this project's Linux
/// tool all promise (and enforce) ASCII bytes, so this must too.
private func isValidServiceByte(_ byte: UInt8) -> Bool {
    (0x30...0x39).contains(byte)      // '0'-'9'
        || (0x41...0x5A).contains(byte) // 'A'-'Z'
        || (0x61...0x7A).contains(byte) // 'a'-'z'
        || byte == 0x2E                 // '.'
}

private func validServiceName(service: String) -> Bool {
    let bytes = service.utf8
    guard !bytes.isEmpty, bytes.count <= hkdfguardMaxServiceLength else {
        return false
    }
    return bytes.allSatisfy(isValidServiceByte)
}

/// Every C ABI entry point below calls this immediately after receiving
/// the raw C string, before any keychain/crypto use. It validates first
/// and lowercases second — in that order, because Unicode case-folding
/// can change byte length and map non-ASCII input onto ASCII (KELVIN SIGN
/// U+212A lowercases to plain `k`), so lowercasing before validation
/// would let such input through. After `validServiceName` has confirmed
/// pure ASCII, an ASCII-only lowercase is exact and length-preserving.
///
/// Service names are case-insensitive (`"Com.Example.App"` and
/// `"com.example.app"` resolve to the same KEK); the returned string is
/// the one normalized form that `validServiceName` re-checks downstream,
/// the keychain query/store calls use, and the AES-GCM AAD / HKDF info
/// bytes are built from. Returns `nil` when the name is invalid — the
/// caller maps that to `invalidServiceIdentifier`.
private func normalizedService(from servicePtr: UnsafePointer<CChar>) -> String? {
    let raw = String(cString: servicePtr)
    guard validServiceName(service: raw) else { return nil }
    let lowered = raw.utf8.map { byte in
        (0x41...0x5A).contains(byte) ? byte + 0x20 : byte
    }
    return String(decoding: lowered, as: UTF8.self)
}

/// Outcome of looking up a service's keychain item. `notFound` is the only
/// case that means "no key exists"; the other two failure cases mean the
/// keychain would not or could not answer, and a key may well exist — the
/// callers below must never treat those as a clean slate.
private enum KEKLookup {
    case found(Data)
    case notFound
    /// Locked keychain / no UI session, ACL denial, user declined the
    /// prompt, or missing entitlement — see `HKDFGuardStatus.keychainAccessDenied`.
    case accessDenied
    case failed(OSStatus)
}

/// Looks up the persisted Secure Enclave key's opaque data representation
/// in the keychain, under the caller-supplied service identifier.
private func loadKEKDataRepresentation(service: String, mode: KeychainMode) -> KEKLookup {
    var query = keychainItemAttributes(service: service, mode: mode)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
        guard let data = item as? Data else { return .failed(errSecInternalError) }
        return .found(data)
    case errSecItemNotFound:
        return .notFound
    case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled, errSecMissingEntitlement:
        return .accessDenied
    default:
        return .failed(status)
    }
}

/// Reconstructs a Secure Enclave key from a keychain item's stored data.
/// `nil` means the item is present but is not (or is no longer) a usable
/// key for this device — `HKDFGuardStatus.kekCorrupted`.
private func reconstructKEK(_ data: Data) -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
    try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
}

@discardableResult
private func storeKEKDataRepresentation(_ data: Data, service: String, mode: KeychainMode) -> OSStatus {
    var attributes = keychainItemAttributes(service: service, mode: mode)
    attributes[kSecValueData as String] = data
    // Honored by the data-protection keychain; accepted but ignored by the
    // legacy keychain, where the login keychain's own lock applies instead.
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    return SecItemAdd(attributes as CFDictionary, nil)
}

/// Reports whether a valid, reconstructable KEK already exists for
/// `service`, without creating one. Distinguishes "no key yet" (`success`,
/// `false`) from "a keychain item is present but can't be reconstructed"
/// (`kekCorrupted`, `false`) — a caller that only looked at the boolean
/// would otherwise treat a corrupt/foreign entry the same as a clean slate.
func kekExists(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> (status: Int32, exists: Bool) {
    guard validServiceName(service: service) else {
        return (HKDFGuardStatus.invalidServiceIdentifier.rawValue, false)
    }

    guard SecureEnclave.isAvailable else {
        return (HKDFGuardStatus.enclaveUnavailable.rawValue, false)
    }

    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .notFound:
        return (HKDFGuardStatus.success.rawValue, false)
    case .accessDenied:
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, false)
    case .failed:
        return (HKDFGuardStatus.keychainReadFailed.rawValue, false)
    case .found(let existing):
        guard reconstructKEK(existing) != nil else {
            return (HKDFGuardStatus.kekCorrupted.rawValue, false)
        }
        return (HKDFGuardStatus.success.rawValue, true)
    }
}

/// Creates a KEK for `service` if one doesn't already exist. Idempotent
/// and safe under concurrent first-use — see the duplicate-item handling
/// below — so a caller that already checked `kekExists` and got `false`
/// doesn't need to treat a race against another creator as its own error.
func createKEK(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> Int32 {

    // Validate service identifier.
    guard validServiceName(service: service) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    // Secure Enclave must exist.
    guard SecureEnclave.isAvailable else {
        return HKDFGuardStatus.enclaveUnavailable.rawValue
    }

    // Existing key? Only a definite "not found" may proceed to create one:
    // a denied or failed lookup means a key may already exist that this
    // process simply can't see, and generating a replacement on top of it
    // would orphan whatever that key protects.
    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .found(let existing):
        guard reconstructKEK(existing) != nil else {
            // Item exists but cannot be reconstructed.
            // Do NOT generate a replacement key.
            return HKDFGuardStatus.kekCorrupted.rawValue
        }
        return HKDFGuardStatus.success.rawValue
    case .accessDenied:
        return HKDFGuardStatus.keychainAccessDenied.rawValue
    case .failed:
        return HKDFGuardStatus.keychainReadFailed.rawValue
    case .notFound:
        break
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

    // The SEP-wrapped key blob is the very credential the keychain item
    // exists to protect: usable by any process on this device that holds
    // it, while unlocked. Zero this process's copy on every exit path once
    // the keychain has it -- including the race-loser path below, where it
    // is never stored at all and would otherwise linger until deallocation.
    var representation = newKey.dataRepresentation
    defer {
        _ = representation.withUnsafeMutableBytes { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
        }
    }

    let status = storeKEKDataRepresentation(
        representation,
        service: service,
        mode: mode
    )

    switch status {

    case errSecSuccess:

        // Verify store/reload/reconstruct succeeds.
        switch loadKEKDataRepresentation(service: service, mode: mode) {
        case .found(let stored) where reconstructKEK(stored) != nil:
            return HKDFGuardStatus.success.rawValue
        case .accessDenied:
            return HKDFGuardStatus.keychainAccessDenied.rawValue
        case .found, .notFound, .failed:
            return HKDFGuardStatus.kekVerificationFailed.rawValue
        }

    case errSecDuplicateItem:

        // Another thread/process won the race. Validate the winner's key
        // before declaring success. If the winner was a differently-signed
        // process, its item's ACL may deny this one — that is
        // keychainAccessDenied, not a corrupt item.
        switch loadKEKDataRepresentation(service: service, mode: mode) {
        case .found(let existing):
            guard reconstructKEK(existing) != nil else {
                return HKDFGuardStatus.kekCorrupted.rawValue
            }
            return HKDFGuardStatus.success.rawValue
        case .accessDenied:
            return HKDFGuardStatus.keychainAccessDenied.rawValue
        case .notFound, .failed:
            return HKDFGuardStatus.keychainReadFailed.rawValue
        }

    case errSecMissingEntitlement, errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled:
        // Normally caught by the lookup above; kept so a write that is
        // refused for access reasons is never reported as a generic write
        // failure.
        return HKDFGuardStatus.keychainAccessDenied.rawValue

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
func getKEK(service: String, mode: KeychainMode = hkdfguardKeychainMode) -> (status: Int32, key: SecureEnclave.P256.KeyAgreement.PrivateKey?) {
    guard validServiceName(service: service) else {
        return (HKDFGuardStatus.invalidServiceIdentifier.rawValue, nil)
    }

    guard SecureEnclave.isAvailable else {
        return (HKDFGuardStatus.enclaveUnavailable.rawValue, nil)
    }

    switch loadKEKDataRepresentation(service: service, mode: mode) {
    case .notFound:
        return (HKDFGuardStatus.kekNotFound.rawValue, nil)
    case .accessDenied:
        return (HKDFGuardStatus.keychainAccessDenied.rawValue, nil)
    case .failed:
        return (HKDFGuardStatus.keychainReadFailed.rawValue, nil)
    case .found(let existing):
        guard let key = reconstructKEK(existing) else {
            return (HKDFGuardStatus.kekCorrupted.rawValue, nil)
        }
        return (HKDFGuardStatus.success.rawValue, key)
    }
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

    // The output size is a constant, so a too-small buffer is reported here
    // -- before any keychain lookup or Secure Enclave operation, and without
    // ever producing a ciphertext the caller cannot receive.
    guard Int(outLen.pointee) >= hkdfguardWrappedLength else {
        outLen.pointee = Int32(hkdfguardWrappedLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
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

/// Reports which keychain this process's KEK items live in — see
/// `KeychainMode`. `*outMode` is 0 for the legacy login keychain and 1 for
/// the data-protection keychain, and is written on every return path.
/// Callers should surface this (the CLI prints it) because a service's
/// provisioner and its consumers must agree on it.
@_cdecl("hkdfguard_keychain_mode")
public func hkdfguard_keychain_mode(
    outMode: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outMode else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    switch hkdfguardKeychainMode {
    case .legacy:
        outMode.pointee = 0
    case .dataProtection:
        outMode.pointee = 1
    }
    return HKDFGuardStatus.success.rawValue
}

/// Reports whether a Secure Enclave KEK already exists for `service`,
/// without creating one — `*outExists` is always written, on every return
/// path (1 if a valid KEK exists, 0 otherwise, including when the status
/// isn't `success`, in which case existence couldn't be determined), so
/// the caller's variable is never left in an undefined state.
@_cdecl("hkdfguard_kek_exists")
public func hkdfguard_kek_exists(
    servicePtr: UnsafePointer<CChar>?,
    outExists: UnsafeMutablePointer<Int32>?
) -> Int32 {
    // NULL from a C caller is a contract violation, reported rather than
    // dereferenced -- here and in every entry point below.
    guard let outExists else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    outExists.pointee = 0

    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let (status, exists) = kekExists(service: service)
    outExists.pointee = exists ? 1 : 0
    return status
}

/// Writes the 32-byte fingerprint (SHA-256 of the public key) of the KEK
/// `service` currently resolves to -- the same value embedded at the front
/// of every payload wrapped under it. Public-key material only, so safe to
/// expose; lets an operator pin which KEK a service uses and confirm it
/// before retiring it. Never creates a KEK.
@_cdecl("hkdfguard_kek_fingerprint")
public func hkdfguard_kek_fingerprint(
    servicePtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard Int(outLen.pointee) >= hkdfguardFingerprintLength else {
        outLen.pointee = Int32(hkdfguardFingerprintLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let (status, maybeKey) = getKEK(service: service)
    guard let key = maybeKey else {
        return status
    }

    let fingerprint = kekFingerprint(publicKeyRaw: key.publicKey.rawRepresentation)
    _ = fingerprint.withUnsafeBytes { raw in
        memcpy(outPtr, raw.baseAddress!, fingerprint.count)
    }
    outLen.pointee = Int32(fingerprint.count)
    return HKDFGuardStatus.success.rawValue
}

/// Creates a Secure Enclave KEK for `service` if one doesn't already
/// exist. Paired with `hkdfguard_kek_exists` above so a caller can decide
/// for itself whether creation is needed — e.g. prompting for user
/// consent, or provisioning on a schedule — rather than have that decision
/// made implicitly inside a single combined "ensure" call.
@_cdecl("hkdfguard_create_kek")
public func hkdfguard_create_kek(
    servicePtr: UnsafePointer<CChar>?
) -> Int32 {
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    return createKEK(service: service)
}

@_cdecl("hkdfguard_wrap_dek")
public func hkdfguard_wrap_dek(
    servicePtr: UnsafePointer<CChar>?,
    dekPtr: UnsafePointer<UInt8>?,
    dekLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let dekPtr, let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
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
    servicePtr: UnsafePointer<CChar>?,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }
    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
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
    servicePtr: UnsafePointer<CChar>?,
    wrappedPtr: UnsafePointer<UInt8>?,
    wrappedLen: Int32,
    outPtr: UnsafeMutablePointer<UInt8>?,
    outLen: UnsafeMutablePointer<Int32>?
) -> Int32 {
    guard let wrappedPtr, let outPtr, let outLen else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    // Every payload this library produces is exactly hkdfguardWrappedLength
    // bytes, so anything else is rejected before it is read.
    guard wrappedLen == Int32(hkdfguardWrappedLength) else {
        return HKDFGuardStatus.invalidInputLength.rawValue
    }

    // The plaintext size is a constant too: a too-small buffer is reported
    // before any keychain lookup or Secure Enclave operation, so a DEK is
    // never decrypted into memory for a caller who cannot receive it.
    guard Int(outLen.pointee) >= hkdfguardDekLength else {
        outLen.pointee = Int32(hkdfguardDekLength)
        return HKDFGuardStatus.outputBufferTooSmall.rawValue
    }

    guard let servicePtr, let service = normalizedService(from: servicePtr) else {
        return HKDFGuardStatus.invalidServiceIdentifier.rawValue
    }

    let fixedPrefixLength = hkdfguardFingerprintLength + hkdfguardEphemeralPublicKeyLength

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
