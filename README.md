# KeyProtectionCore-MacOS

Core Key and Key Material Protection for macOS interop across HkdfGuard libraries.

`HkdfGuardKeyProtectionEnclave` wraps and unwraps Data Encryption Keys (DEKs)
using a Secure Enclave–backed key, exposed as a plain C ABI so it can be
called from Swift, Objective-C, or any other language capable of loading a
Mach-O framework/dylib and calling C functions (Python `ctypes`, Go `cgo`,
Node, C#, Java JNA, etc.).

## What it does

Each calling application identifies itself with a **service string** (see
below). The first time a given service wraps or unwraps anything, the
library generates a P-256 key pair inside the device's Secure Enclave and
persists an opaque, device-bound reference to it in the keychain — the
private key material itself never leaves the Secure Enclave and can never be
extracted, only used via hardware-mediated operations.

To wrap a 32-byte DEK:

1. Generate a fresh ephemeral P-256 key pair (discarded after this call).
2. Perform ECDH between the ephemeral private key and the service's Secure
   Enclave public key (the enclave does its side of the exchange in
   hardware).
3. Derive an AES-256 key from the resulting shared secret via HKDF-SHA256,
   salted with the ephemeral public key.
4. Encrypt the DEK with AES-GCM under that derived key.
5. Output the ephemeral public key alongside the AES-GCM ciphertext — the
   receiver needs the ephemeral public key to reconstruct the same shared
   secret, since it's generated fresh per call and never stored anywhere.

Unwrapping reverses this, with the Secure Enclave performing its side of the
ECDH using its persisted private key. This is a standard ECIES construction;
it's what gives two wraps of the same DEK under the same service different
ciphertext every time (see `twoWrapsOfSameDEKProduceDifferentCiphertext` in
the test suite), and it means an unwrap under one service can never succeed
against a blob wrapped under a different service — each service gets its own
independent Secure Enclave key, fully isolated from every other service's.

## Wrapped format

```
[ephemeral P-256 public key, 64 bytes raw (x || y)]
[AES-GCM combined: 12-byte nonce || ciphertext || 16-byte tag]
```

For a 32-byte DEK this is always exactly **124 bytes** (64 + 12 + 32 + 16).

## C ABI

Declared in [`HkdfGuardKeyProtectionEnclave.h`](HkdfGuardKeyProtectionEnclave/HkdfGuardKeyProtectionEnclave.h):

```c
int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek,
    int32_t dek_len,
    uint8_t* out,
    int32_t* out_len
);

int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped,   // the wrapped blob produced by wrap_dek
    int32_t wrapped_len,
    uint8_t* out,
    int32_t* out_len
);
```

- **`service`** — a non-empty, null-terminated UTF-8 string identifying the
  calling application. Pick one identifier per application and keep it
  stable; wrapping under one service and unwrapping under another will fail
  by design.
- **`out`/`out_len`** — on entry, `*out_len` is the capacity of `out`; on
  return, it's always set to either the number of bytes actually written
  (on success) or the number of bytes that would have been required (if the
  call failed with `outputBufferTooSmall`), so a caller can size a buffer
  correctly on a second attempt without guessing.
- The keychain **account** suffix used alongside `service` (`"kek-v1"`) is
  fixed and internal — only the service varies per caller.

### Status codes

| Value | Meaning |
|------:|---------|
|   `0` | success |
|  `-1` | `invalidInputLength` — `dek_len`/wrapped blob length is wrong |
|  `-2` | `outputBufferTooSmall` — `*out_len` has been set to the required size |
|  `-3` | `keyUnavailable` — the Secure Enclave key could not be obtained |
|  `-4` | `publicKeyUnavailable` |
|  `-5` | `encryptionFailed` |
|  `-6` | `decryptionFailed` — also returned for a wrong/mismatched service |
|  `-7` | `unexpectedOutputLength` |
|  `-8` | `missingServiceIdentifier` — `service` was `NULL` or empty |

## Project layout

Three targets, all built from the same `HkdfGuardKeyProtectionEnclave.swift`:

| Target | Product | Use case |
|---|---|---|
| `HkdfGuardKeyProtectionEnclave` | `HkdfGuardKeyProtectionEnclave.framework` | Embed in a signed macOS app; carries the public header and an app-sandbox entitlement |
| `HkdfGuardKeyProtectionEnclaveDylib` | `hkdfguardkeyprotectionenclave.dylib` | Flat shared library for `dlopen`-based FFI from Python/Go/Node/C#/Java — no entitlements attached, since it's meant to load into arbitrary, often unsandboxed, host processes |
| `HkdfGuardKeyProtectionEnclaveTests` | `HkdfGuardKeyProtectionEnclaveTests.xctest` | Swift Testing suite exercising the C entry points directly |

Requires **Swift 6.2+** and **macOS 13.0+** (enforced at compile time via a
`#error` guard in the source, and separately at runtime by the deployment
target).

## Building

```sh
# Framework, embeddable in a signed app:
xcodebuild -project HkdfGuardKeyProtectionEnclave.xcodeproj \
  -scheme HkdfGuardKeyProtectionEnclave -configuration Release build

# Standalone dylib for cross-language FFI:
xcodebuild -project HkdfGuardKeyProtectionEnclave.xcodeproj \
  -scheme HkdfGuardKeyProtectionEnclaveDylib -configuration Release build

# Tests:
xcodebuild test -project HkdfGuardKeyProtectionEnclave.xcodeproj \
  -scheme HkdfGuardKeyProtectionEnclaveTests -destination 'platform=macOS'
```

Both the framework and dylib targets use `CODE_SIGN_STYLE = Automatic`.
The project currently carries a specific `DEVELOPMENT_TEAM` and
`PRODUCT_BUNDLE_IDENTIFIER` — **replace both with your own Apple Developer
Team ID and reverse-DNS identifier** before building under your own account
(Xcode → target → Signing & Capabilities).

## Signing and entitlements

- The **framework** target has `com.apple.security.app-sandbox` enabled.
  It deliberately does *not* declare a `keychain-access-groups` entitlement:
  that capability is enforced against a process's main executable, not each
  framework it loads, and Xcode won't even let it be attached to a Framework
  target. If cross-process keychain sharing is ever needed, that entitlement
  belongs on the actual app target that embeds this framework, with the code
  updated to pass a matching `kSecAttrAccessGroup`.
- The **dylib** target has no entitlements at all, on purpose, since it's
  meant to be loaded into arbitrary host processes that may not be
  sandboxed.
- Keychain items are looked up as `(service, account: "kek-v1")` generic
  passwords with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — they never
  sync via iCloud Keychain and are bound to this device's Secure Enclave.

## Concurrency notes

- `getOrCreateKEK` is safe under concurrent first-use for a given service:
  if multiple callers race to create the very first keychain item for a
  service, the keychain's unique index on `(service, account)` lets exactly
  one creation win, and the losing callers fall back to loading the
  winner's key rather than failing.
- That said, the Secure Enclave/`securityd` IPC layer itself has limited
  real concurrent-request capacity — pushing many *simultaneous* wrap/unwrap
  calls at it (observed directly while building this project's own test
  suite) causes severe contention, not just slowness. Avoid firing off large
  numbers of concurrent Secure Enclave operations from a single process; a
  handful of concurrent calls is fine, dozens is not.

## Tests

The test suite (`HkdfGuardKeyProtectionEnclaveTests.swift`) runs serialized
(`@Suite(.serialized)`) for the reason above, and covers: round-trip
correctness, wrapped-output length/format, ephemeral-nonce non-determinism,
per-service key isolation, input validation (bad DEK length, missing
service, empty service), output-buffer-too-small size reporting, AES-GCM
tamper detection, and a regression test for the concurrent-first-use
provisioning race. Every test that provisions a Secure Enclave key deletes
its keychain item in a `defer`, so a failing test still leaves the keychain
clean.
