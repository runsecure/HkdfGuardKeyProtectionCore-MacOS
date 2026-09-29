//
//  HkdfGuardKeyProtectionEnclave.h
//  HkdfGuardKeyProtectionEnclave
//
//  Public C ABI of the HkdfGuard macOS key-protection library: wraps and
//  unwraps 32-byte Data Encryption Keys (DEKs) under a per-service Key
//  Encryption Key (KEK) held in the Secure Enclave.
//
//  Plain C. Includable from C, C++, Objective-C, and any FFI layer
//  (P/Invoke, ctypes, cgo, JNA) without Foundation; the Objective-C-only
//  framework version symbols are guarded below so they never get in a C
//  consumer's way.
//

#ifndef HKDFGUARD_MACOS_H
#define HKDFGUARD_MACOS_H

#ifdef __OBJC__
#import <Foundation/Foundation.h>

//! Project version number for HkdfGuardKeyProtectionEnclave.
FOUNDATION_EXPORT double HkdfGuardKeyProtectionEnclaveVersionNumber;

//! Project version string for HkdfGuardKeyProtectionEnclave.
FOUNDATION_EXPORT const unsigned char HkdfGuardKeyProtectionEnclaveVersionString[];
#endif

#include <stdint.h>

// Every pointer parameter below is required. Under clang that is checked
// at the call site; elsewhere this macro is documentation. At run time a
// NULL is never dereferenced: it is reported as invalidInputLength (-1),
// or as invalidServiceIdentifier (-8) when it is `service`.
#if defined(__clang__)
#  define HKDFGUARD_NONNULL _Nonnull
#else
#  define HKDFGUARD_NONNULL
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Status codes returned by every function below
// ---------------------------------------------------------------------------
//    0  success
//   -1  invalidInputLength     (dek_len != 32, wrapped_len != 156, or a NULL
//                               buffer/length pointer)
//   -2  outputBufferTooSmall   (*out_len has been set to the required size:
//                               156 for wrap, 32 for unwrap. Reported before
//                               any keychain or Secure Enclave work, so a
//                               caller can size a buffer with a first call
//                               that costs nothing)
//   -3  keyUnavailable         (reserved; no longer returned -- see -10 and
//                               lower for the specific failures this used
//                               to lump together)
//   -4  publicKeyUnavailable
//   -5  encryptionFailed
//   -6  decryptionFailed       (AES-GCM authentication failed: the payload
//                               or its embedded fingerprint was altered, or
//                               it was wrapped for a different service under
//                               the same KEK. A different service's KEK is
//                               caught earlier, as fingerprintMismatch)
//   -7  unexpectedOutputLength
//   -8  invalidServiceIdentifier (service was NULL, empty, longer than 128
//                                 bytes, or contained a byte other than an
//                                 ASCII letter, digit, or '.')
//   -9  enclaveUnavailable       (no Secure Enclave on this machine)
//  -10  kekNotFound              (no keychain item exists for this service
//                                 in this process's keychain mode -- the
//                                 ordinary state before hkdfguard_create_kek
//                                 has been called. Returned by every wrap/
//                                 unwrap function, which never create one)
//  -11  kekCorrupted             (a keychain item exists under this service
//                                 but could not be reconstructed into a
//                                 usable key -- a corrupt or foreign entry;
//                                 never "healed" by generating a replacement)
//  -12  accessControlCreationFailed (failed to set up the access policy for
//                                    a new KEK, before any Secure Enclave key
//                                    was requested)
//  -13  keyGenerationFailed      (the Secure Enclave refused to generate a
//                                 new key)
//  -14  keychainWriteFailed      (SecItemAdd failed persisting a newly
//                                 generated KEK, for a reason other than a
//                                 concurrent creator winning the race or an
//                                 access denial)
//  -15  kekVerificationFailed    (a KEK was generated and stored, but could
//                                 not be reloaded immediately afterward;
//                                 should not happen)
//  -16  fingerprintMismatch      (the payload's embedded KEK fingerprint
//                                 doesn't match the public key of the KEK
//                                 this service currently resolves to: it was
//                                 not wrapped under the key hkdfguard_unwrap_dek
//                                 is about to use. Detected before any ECDH
//                                 or AES-GCM is attempted -- "wrong KEK",
//                                 as distinct from decryptionFailed's "right
//                                 KEK, altered data")
//  -17  keychainAccessDenied     (the keychain would not say whether an item
//                                 exists: it is locked or there is no UI
//                                 session to prompt in, the item's ACL
//                                 denied this process or the user declined
//                                 the access prompt, or a required
//                                 entitlement is missing. A key very likely
//                                 DOES exist -- do not treat this as
//                                 kekNotFound and create a replacement, and
//                                 do not treat it as kekCorrupted and delete
//                                 anything)
//  -18  keychainReadFailed       (SecItemCopyMatching failed for a reason
//                                 other than not-found or the access-denial
//                                 conditions above)

// ---------------------------------------------------------------------------
// `service`
// ---------------------------------------------------------------------------
// A null-terminated string of 1-128 bytes, each an ASCII letter, digit, or
// '.', identifying the calling application -- typically reverse-DNS. It is
// matched case-insensitively: every function lowercases it before
// validation, storage, or lookup, so "Com.Example.App" and "com.example.app"
// refer to the same KEK. Each distinct service gets its own, independent
// Secure Enclave key; wrapping under one service and unwrapping under
// another fails by design.
//
// The service name is also how payload-format versions are distinguished:
// a consumer that changes format adopts a new service name (and therefore
// a new KEK) rather than relying on an in-band version field.

// ---------------------------------------------------------------------------
// Buffer contract
// ---------------------------------------------------------------------------
// Lengths are trusted: `dek_len`, `wrapped_len`, and `*out_len` on entry
// must describe real, readable/writable memory of exactly that size. A
// wrapped payload is always exactly 156 bytes:
//
//   [ 32-byte KEK fingerprint (SHA-256 of the KEK's public key) ]
//   [ 64-byte ephemeral P-256 public key, raw x || y                ]
//   [ 12-byte AES-GCM nonce || 32-byte ciphertext || 16-byte tag    ]
//
// On return, `*out_len` is always set: to the bytes written on success, or
// to the required size on outputBufferTooSmall.

// ---------------------------------------------------------------------------
// Keychain mode (hybrid)
// ---------------------------------------------------------------------------
// The KEK's keychain item lives in one of two keychains, chosen once per
// process from that process's own code-signing entitlements -- never from
// configuration:
//
//   data-protection (mode 1): the process carries a `keychain-access-groups`
//       entitlement, which on macOS requires a Team-signed app bundle with
//       an embedded provisioning profile. Items are stored under the FIRST
//       listed access group, and access is decided by securityd from the
//       caller's signed identity: no prompts, no per-item ACLs, and any
//       Team-signed bundle listing the same group shares the item. This is
//       the hardened mode -- put the shared HkdfGuard group first (or make
//       it the only one) in every participating bundle's entitlement.
//   legacy (mode 0): no such entitlement -- a bare executable (the
//       hkdfguard-v1-initialize CLI as a plain Mach-O, a .NET/Python/Go
//       host that dlopens this library). Items are stored in the login
//       keychain, protected by its lock and a per-item ACL keyed to the
//       creating binary's signature; other identities get an interactive
//       prompt, or, headless, keychainAccessDenied (-17).
//
// The two keychains are disjoint, so the process that provisions a
// service's KEK and every process that unwraps under it MUST run in the
// same mode; a mismatch surfaces as kekNotFound (-10). Query the mode with
// hkdfguard_keychain_mode and surface it wherever KEKs are provisioned
// (the CLI prints it).

// ---------------------------------------------------------------------------
// Access policy (fixed) and headless use
// ---------------------------------------------------------------------------
// Every KEK is created with kSecAttrAccessibleWhenUnlockedThisDeviceOnly and
// privateKeyUsage only -- no user-presence or biometric requirement, so no
// Touch ID/password prompt is ever needed to use it (this library serves
// unattended services). Consequences:
//
//   - The key can never leave this device: no backup or restore carries it.
//   - "Unlocked" is the login user's keybag. A LaunchDaemon or SSH session
//     on a Mac with no unlocked GUI session may find the key unavailable,
//     surfacing as keyGenerationFailed/decryptionFailed from the enclave or
//     keychainAccessDenied from a locked keychain. Run headless consumers
//     as a LaunchAgent inside a logged-in session, or otherwise ensure the
//     login keychain is unlocked.
//   - The protection boundary is "which processes may read the keychain
//     item" (the keychain mode's job), not "a human approved this use".
//
// There is no per-service policy override.

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

// Writes 0 (legacy login keychain) or 1 (data-protection keychain) to
// `*out_mode` -- see "Keychain mode" above.
int32_t hkdfguard_keychain_mode(
    int32_t* HKDFGUARD_NONNULL out_mode);

// Reports whether a Secure Enclave KEK already exists for `service`,
// without creating one. `*out_exists` is written on every return path --
// 1 if a valid KEK exists, 0 otherwise (including whenever the return
// status isn't 0, in which case existence couldn't be determined).
//
// kekCorrupted (-11) here means an item exists under this service but
// could not be reconstructed into a usable key -- distinct from "no key
// yet" (0, *out_exists = 0). Treat it as an error to investigate, not as
// "safe to create a new one". keychainAccessDenied (-17) means the
// keychain would not answer; a key may well exist.
int32_t hkdfguard_kek_exists(
    const char* HKDFGUARD_NONNULL service,
    int32_t* HKDFGUARD_NONNULL out_exists);

// Creates a Secure Enclave KEK for `service` if one doesn't already exist.
// Idempotent, and safe under concurrent first use by several threads or
// processes: whoever wins the race creates it, everyone else finds it, and
// all return 0 provided the resulting key can be reconstructed. The only
// function in this library that creates a key.
int32_t hkdfguard_create_kek(
    const char* HKDFGUARD_NONNULL service);

// Wraps the 32-byte DEK at `dek` under the KEK for `service` and writes the
// 156-byte payload to `out`. Never creates a KEK: expects kekNotFound (-10)
// if hkdfguard_create_kek has not been called for this service in this
// process's keychain mode.
int32_t hkdfguard_wrap_dek(
    const char* HKDFGUARD_NONNULL service,
    const uint8_t* HKDFGUARD_NONNULL dek,
    int32_t dek_len,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len
);

// Unwraps a 156-byte payload produced by hkdfguard_wrap_dek or
// hkdfguard_generate_and_wrap_dek, writing the 32-byte DEK to `out`. Checks
// the payload's embedded KEK fingerprint against the KEK `service` resolves
// to before attempting any ECDH or AES-GCM, failing with fingerprintMismatch
// (-16) on a different KEK. Never creates a KEK.
int32_t hkdfguard_unwrap_dek(
    const char* HKDFGUARD_NONNULL service,
    const uint8_t* HKDFGUARD_NONNULL wrapped,
    int32_t wrapped_len,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len
);

// Generates a fresh, cryptographically random 32-byte DEK from the OS
// CSPRNG and immediately wraps it under the KEK for `service`, in one call
// -- the caller only ever sees the wrapped form, and the library zeroes its
// own copy before returning. For callers that want a brand-new DEK without
// sourcing their own randomness. Never creates a KEK.
int32_t hkdfguard_generate_and_wrap_dek(
    const char* HKDFGUARD_NONNULL service,
    uint8_t* HKDFGUARD_NONNULL out,
    int32_t* HKDFGUARD_NONNULL out_len
);

#ifdef __cplusplus
}
#endif

#endif
