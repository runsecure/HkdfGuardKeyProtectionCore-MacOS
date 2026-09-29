//
//  HkdfGuardKeyProtectionEnclave.h
//  HkdfGuardKeyProtectionEnclave
//

#import <Foundation/Foundation.h>

//! Project version number for HkdfGuardKeyProtectionEnclave.
FOUNDATION_EXPORT double HkdfGuardKeyProtectionEnclaveVersionNumber;

//! Project version string for HkdfGuardKeyProtectionEnclave.
FOUNDATION_EXPORT const unsigned char HkdfGuardKeyProtectionEnclaveVersionString[];

// In this header, import any public headers of the framework that should be
// visible to Objective-C consumers, e.g.:
// #import <HkdfGuardKeyProtectionEnclave/PublicHeader.h>

#ifndef HKDFGUARD_MACOS_H
#define HKDFGUARD_MACOS_H

#include <stdint.h>

// Status codes returned by the functions below:
//    0  success
//   -1  invalidInputLength     (dek_len or wrapped_len is wrong)
//   -2  outputBufferTooSmall   (*out_len is set to the required size)
//   -3  keyUnavailable         (reserved; no longer returned by anything
//                               below -- see -10 and lower for the specific
//                               KEK-lifecycle failures this used to lump
//                               together)
//   -4  publicKeyUnavailable
//   -5  encryptionFailed
//   -6  decryptionFailed       (also returned for a wrong/mismatched service)
//   -7  unexpectedOutputLength
//   -8  invalidServiceIdentifier (service was NULL, empty, longer than 128
//                                 characters, or contained a character other
//                                 than an ASCII letter, digit, or '.')
//   -9  enclaveUnavailable       (Secure Enclave is not available on this
//                                 machine)
//  -10  kekNotFound              (no keychain item exists yet for this
//                                 service -- the ordinary state before the
//                                 first hkdfguard_create_kek call; returned
//                                 by hkdfguard_wrap_dek/hkdfguard_unwrap_dek,
//                                 which no longer create one implicitly)
//  -11  kekCorrupted             (a keychain item exists under this service,
//                                 but couldn't be reconstructed into a usable
//                                 key -- a corrupt or foreign entry; never
//                                 "healed" by generating a replacement)
//  -12  accessControlCreationFailed (failed to set up the access control
//                                    for a new KEK, before any Secure
//                                    Enclave key was requested)
//  -13  keyGenerationFailed      (the Secure Enclave refused to generate a
//                                 new key for this service)
//  -14  keychainWriteFailed      (SecItemAdd failed persisting a newly
//                                 generated KEK, for a reason other than a
//                                 concurrent creator winning the race)
//  -15  kekVerificationFailed    (a KEK was generated and stored, but
//                                 reloading/reconstructing it immediately
//                                 afterward failed; should not happen)
//  -16  fingerprintMismatch      (the wrapped payload's embedded KEK
//                                 fingerprint doesn't match the public key
//                                 of the KEK this service currently
//                                 resolves to -- this payload was not
//                                 wrapped under the key hkdfguard_unwrap_dek
//                                 is about to use. Detected before any
//                                 ECDH/AES-GCM is attempted -- unlike
//                                 decryptionFailed, this specifically means
//                                 "wrong KEK," not "right KEK, but
//                                 tampered/mismatched data")
//  -17  keychainAccessDenied     (the keychain would not say whether an
//                                 item exists: it is locked or there is no
//                                 UI session to prompt in, the item's ACL
//                                 denied this process or the user declined
//                                 the access prompt, or a required
//                                 entitlement is missing. A key very likely
//                                 DOES exist -- do not treat this as
//                                 kekNotFound and create a replacement, and
//                                 do not treat it as kekCorrupted and
//                                 delete anything)
//  -18  keychainReadFailed       (SecItemCopyMatching failed for a reason
//                                 other than not-found or the access-denial
//                                 conditions above)
//
// `service` is matched case-insensitively -- every function below
// lowercases it before validation, storage, or lookup, so
// "Com.Example.App" and "com.example.app" always refer to the same KEK.
//
// Keychain mode (hybrid). The KEK's keychain item lives in one of two
// keychains, chosen once per process from that process's own code-signing
// entitlements -- never from configuration:
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
// hkdfguard_keychain_mode below and surface it wherever KEKs are
// provisioned (the CLI prints it).

// Writes 0 (legacy login keychain) or 1 (data-protection keychain) to
// `*out_mode` -- see "Keychain mode" above. Always succeeds; `*out_mode`
// is written on every return path.
int32_t hkdfguard_keychain_mode(
    int32_t* out_mode);

// Reports whether a Secure Enclave KEK already exists for `service`,
// without creating one. `*out_exists` is always written on every return
// path -- 1 if a valid KEK exists, 0 otherwise (including when the return
// status isn't 0/success, in which case existence couldn't be determined)
// -- so the caller's variable is never left in an undefined state.
//
// A `kekCorrupted` (-11) return here specifically means a keychain item
// exists under this service but could not be reconstructed into a usable
// key -- a corrupt or foreign entry -- distinct from "no key yet" (success,
// *out_exists = 0). Treat that as an error to investigate, not as "safe to
// create a new one".
int32_t hkdfguard_kek_exists(
    const char* service,
    int32_t* out_exists);

// Creates a Secure Enclave KEK for `service` if one doesn't already exist.
// Safe to call when one already does, including a concurrent creation by
// another thread/process -- returns success either way, provided the
// resulting key can be reconstructed. Pair this with hkdfguard_kek_exists
// above when the caller wants to decide for itself whether creation is
// needed (e.g. prompting for consent, or provisioning on a schedule)
// rather than have that decision made implicitly inside one combined call.
int32_t hkdfguard_create_kek(
    const char* service);

// `service` must be a non-empty, null-terminated UTF-8 string identifying
// the calling application. Each distinct service string gets its own,
// independent Secure Enclave key — wrapping under one service's identifier
// and unwrapping under a different one will fail, by design. Neither
// function below creates a KEK that doesn't already exist -- call
// hkdfguard_create_kek first, or expect kekNotFound (-10) back.
int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek,
    int32_t dek_len,
    uint8_t* out,
    int32_t* out_len
);

// Before attempting any decryption, checks the wrapped payload's embedded
// KEK fingerprint against the public key of the KEK `service` currently
// resolves to, failing fast with fingerprintMismatch (-16) if they don't
// match -- see the status code table above.
int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped,
    int32_t wrapped_len,
    uint8_t* out,
    int32_t* out_len
);

// Generates a fresh, cryptographically random 32-byte DEK and immediately
// wraps it under the persistent Secure Enclave KEK identified by `service`,
// in one call — for callers that want a brand new Ephemeral Data Protection
// Key without having to source their own randomness.
int32_t hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out,
    int32_t* out_len
);

#endif
