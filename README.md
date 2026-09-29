# HkdfGuardKeyProtectionCore-MacOS

Core key and key-material protection for macOS, for interop across the
HkdfGuard libraries. Sibling of `HkdfGuardKeyProtectionCore-Linux`.

`HkdfGuardKeyProtectionEnclave` wraps and unwraps 32-byte Data Encryption
Keys (DEKs) under a per-service Key Encryption Key (KEK) that lives in the
device's Secure Enclave, exposed as a plain C ABI so it can be called from
Swift, Objective-C, C/C++, or any language that can load a Mach-O dylib
(Python `ctypes`, Go `cgo`, .NET P/Invoke, Java JNA, …). A companion
command-line tool, `hkdfguard-v1-initialize`, provisions KEKs and wraps DEKs
for pipelines.

## What it does

Each calling application identifies itself with a **service name** (see
below). A service's KEK is a P-256 key-agreement key generated inside the
Secure Enclave; its private half never leaves the enclave and can only be
*used*, never extracted. What the library persists in the keychain is the
enclave's opaque, device-bound reference to that key.

Provisioning is explicit. `hkdfguard_create_kek` is the only function that
creates a KEK; every wrap/unwrap function requires one to already exist and
fails with `kekNotFound` (-10) otherwise. Nothing is ever created "on first
use".

To wrap a DEK:

1. Generate a fresh ephemeral P-256 key pair (discarded after the call).
2. ECDH between the ephemeral private key and the service's KEK public key.
3. Derive an AES-256 key via HKDF-SHA512, salted with the ephemeral public
   key and bound to the scheme label, both public keys, and the service.
4. AES-256-GCM-encrypt the DEK under a random nonce, with the service name
   and the KEK fingerprint as additional authenticated data.

Unwrapping reverses this, with the enclave performing its side of the ECDH.
Because each wrap uses a fresh ephemeral key *and* a fresh nonce, the
derived key is single-use — two wraps of the same DEK never produce the
same bytes — and a payload wrapped under one service can never be opened
under another.

## Wrapped payload format

Always exactly **156 bytes**:

```
[ 32-byte KEK fingerprint — SHA-256 of the KEK's public key ]
[ 64-byte ephemeral P-256 public key, raw x || y             ]
[ 12-byte AES-GCM nonce || 32-byte ciphertext || 16-byte tag ]
```

The fingerprint identifies *which* KEK a payload was wrapped under. On
unwrap it is compared to the current KEK's public key **before** any ECDH
or decryption is attempted, so "wrong or rotated KEK" is reported as
`fingerprintMismatch` (-16) rather than as a generic decryption failure.
It is also folded into the AES-GCM authenticated data, so tampering with it
fails the tag check as well.

There is no in-band format version. **A change of payload format is
signalled by adopting a new service name** (and therefore a new KEK).

## Service names

1–128 bytes, each an ASCII letter, digit, or `.` — typically reverse-DNS.
Matched **case-insensitively**: every entry point lowercases the name before
validation, storage, and lookup. Anything else (empty, over-length, any
non-ASCII byte, `-`, `_`, …) is `invalidServiceIdentifier` (-8). The rule is
enforced on bytes, identically in the library, the CLI, and the Linux tool.

## C ABI

Declared in
[`HkdfGuardKeyProtectionEnclave.h`](HkdfGuardKeyProtectionEnclave/HkdfGuardKeyProtectionEnclave.h)
(plain C; `extern "C"`-guarded; nullability-annotated). All pointers are
required — a NULL is reported, never dereferenced.

```c
int32_t hkdfguard_keychain_mode(int32_t* out_mode);          // 0 legacy, 1 data-protection
int32_t hkdfguard_kek_exists(const char* service, int32_t* out_exists);
int32_t hkdfguard_create_kek(const char* service);            // the only function that creates a KEK
int32_t hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int32_t dek_len,
                           uint8_t* out, int32_t* out_len);
int32_t hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int32_t wrapped_len,
                             uint8_t* out, int32_t* out_len);
int32_t hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int32_t* out_len);
```

`*out_len` is the buffer capacity on entry and, on return, either the bytes
written or — on `outputBufferTooSmall` — the required size (156 for wrap,
32 for unwrap). Both wrap and unwrap check the capacity, and unwrap checks
`wrapped_len == 156`, **before** touching the keychain or the enclave, so a
sizing call costs nothing and a DEK is never decrypted for a caller who
cannot receive it.

### Status codes

| Value | Meaning |
|------:|---------|
| `0`   | success |
| `-1`  | `invalidInputLength` — `dek_len != 32`, `wrapped_len != 156`, or a NULL buffer/length pointer |
| `-2`  | `outputBufferTooSmall` — `*out_len` set to the required size |
| `-3`  | `keyUnavailable` — reserved, no longer returned |
| `-4`  | `publicKeyUnavailable` |
| `-5`  | `encryptionFailed` |
| `-6`  | `decryptionFailed` — AES-GCM authentication failed (altered payload, or wrapped for a different service under the same KEK) |
| `-7`  | `unexpectedOutputLength` |
| `-8`  | `invalidServiceIdentifier` |
| `-9`  | `enclaveUnavailable` — no Secure Enclave on this machine |
| `-10` | `kekNotFound` — no KEK for this service in this process's keychain mode; call `hkdfguard_create_kek` |
| `-11` | `kekCorrupted` — an item exists but can't be reconstructed into a key; never auto-replaced |
| `-12` | `accessControlCreationFailed` |
| `-13` | `keyGenerationFailed` — the enclave refused to generate a key |
| `-14` | `keychainWriteFailed` |
| `-15` | `kekVerificationFailed` — stored, but couldn't be reloaded immediately after |
| `-16` | `fingerprintMismatch` — payload was wrapped under a different KEK |
| `-17` | `keychainAccessDenied` — locked keychain / no UI session / ACL denial / declined prompt / missing entitlement. **A key likely exists**; don't create or delete anything |
| `-18` | `keychainReadFailed` |

## Keychain modes (hybrid)

The KEK's keychain item lives in one of two keychains, chosen once per
process from the process's **own code-signing entitlements** — never from
configuration:

| Mode | When | Where the item lives | Cross-process access |
|---|---|---|---|
| **data-protection** (1) | the process has a `keychain-access-groups` entitlement — on macOS that means a Team-signed **app bundle with an embedded provisioning profile** | the data-protection keychain, under the first listed access group | decided by securityd from the caller's signed identity: no prompts, no ACLs; any Team-signed bundle listing the same group shares it |
| **legacy** (0) | no such entitlement — a bare executable (the CLI as a plain Mach-O, a .NET/Python/Go host that `dlopen`s the dylib, the `xctest` agent) | the login keychain | login-keychain lock plus a per-item ACL keyed to the creating binary; other identities get an interactive prompt, or, headless, `-17` |

The two keychains are disjoint: **the process that provisions a service's
KEK and every process that unwraps under it must run in the same mode**, or
consumers see `kekNotFound`. `hkdfguard_keychain_mode` reports the mode and
the CLI prints it on every command. Both modes set
`kSecAttrSynchronizable = false`; iCloud Keychain never sees these items.

## Access policy and headless use

Every KEK is created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
`privateKeyUsage` only — no user-presence or biometric requirement, so
using the key never triggers a Touch ID/password prompt. Consequences:

- The key can never leave this device; no backup or restore carries it.
- "Unlocked" means the login user's keybag. A LaunchDaemon or SSH session on
  a Mac with no unlocked GUI session may find the key unavailable
  (`keyGenerationFailed`/`decryptionFailed` from the enclave, or
  `keychainAccessDenied` from a locked keychain). Run headless consumers as
  a LaunchAgent in a logged-in session, or ensure the login keychain is
  unlocked.
- The protection boundary is *which processes may read the keychain item*
  (the keychain mode's job), not *a human approved this use*.

The policy is fixed; there is no per-service override, and there is no
delete or rotate API — a service that needs a new KEK adopts a new service
name.

## Command-line tool: `hkdfguard-v1-initialize`

Provisions KEKs and wraps DEKs for pipelines. It calls the library only
through the C ABI above. Two commands:

```
hkdfguard-v1-initialize provision --service-name|-sn <name>

hkdfguard-v1-initialize wrap --key-file-path|-kf <path> \
                             --service-name|-sn <name> \
                             ( --dek-stdin | --dek-file <path> ) \
                             [--force|-f]
```

- **`provision`** creates the KEK for `<name>` if it doesn't exist. The only
  command that creates keys; idempotent (a second run reports "already
  exists" and exits 0). Prints the keychain mode it used.
- **`wrap`** wraps the pipeline's existing 32-byte DEK — base64, read from
  **stdin** (`--dek-stdin`, trailing newline fine) or a **file**
  (`--dek-file`) — under the already-provisioned KEK and writes the 156-byte
  payload to `<path>` with POSIX `0640` permissions set at creation. It
  never creates a KEK (an unprovisioned service is an error naming the
  `provision` command) and never generates a DEK. There is deliberately no
  `--dek <base64>` argument: an argv value is visible to every process via
  `ps` and lands in shell history. `--dek` and `--generate` are refused
  with an explanation.
- **`--force`** securely overwrites an existing `<path>` (eight alternating
  zero/random passes, each `fsync`ed) before replacing it. It only ever
  touches a **regular file**: a symlink at `<path>` is refused rather than
  followed (`O_NOFOLLOW` + `fstat`), as is a FIFO, device, or directory.

Exit codes: `0` success, `1` runtime failure, `2` argument error (usage
printed). Nothing persistent is touched until every argument is validated.

Example pipeline use:

```sh
hkdfguard-v1-initialize provision -sn com.example.ingest
printf '%s' "$DEK_B64" | hkdfguard-v1-initialize wrap -kf /etc/example/ingest.key -sn com.example.ingest --dek-stdin
```

## Project layout

| Target / package | Product | Purpose |
|---|---|---|
| `HkdfGuardKeyProtectionEnclave` | `HkdfGuardKeyProtectionEnclave.framework` | Embed in a signed macOS app; carries the public header and an app-sandbox entitlement |
| `HkdfGuardKeyProtectionEnclaveDylib` | `HkdfGuard.Kms.MacOS.v1.dylib` | Flat shared library for `dlopen`-based FFI from arbitrary, often unsandboxed, host processes |
| `HkdfGuardKeyProtectionEnclaveTests` | `.xctest` | Swift Testing suites for the C entry points and for the CLI as a real subprocess |
| `hkdfguard-v1-initialize/` | `hkdfguard-v1-initialize` | SwiftPM package for the CLI; links the dylib through its C ABI only |

All library targets build from the single `HkdfGuardKeyProtectionEnclave.swift`.
Requires **Swift 6.2+** (compile-time `#error` guard) and **macOS 13.0+**.

## Building

```sh
# Framework, embeddable in a signed app:
xcodebuild -project HkdfGuardKeyProtectionEnclave.xcodeproj \
  -scheme HkdfGuardKeyProtectionEnclave -configuration Release build

# Standalone dylib for FFI:
xcodebuild -project HkdfGuardKeyProtectionEnclave.xcodeproj \
  -target HkdfGuardKeyProtectionEnclaveDylib -configuration Release build

# CLI (links against build/Release by default; override with HKDFGUARD_DYLIB_DIR):
swift build -c release --package-path hkdfguard-v1-initialize

# Tests (real Secure Enclave required — see Tests):
xcodebuild test -scheme HkdfGuardKeyProtectionEnclaveTests
```

### Distribution: `build-dist.sh`

Builds everything a downstream consumer needs into `dist/osx-x64/` and
`dist/osx-arm64/` (dylib, header, CLI, `SHA256SUMS`), one folder per .NET
runtime identifier. For each architecture it builds the dylib and the CLI
natively, rewrites the CLI's rpath to `@executable_path` so it finds the
dylib next to itself, signs both with the **hardened runtime and a secure
timestamp**, then verifies: strict signature check, runtime flag, timestamp,
`lipo` architecture, rpath, `@rpath` reference, and a `--help` launch smoke
test on the host architecture. Everything is assembled in a staging
directory and only moved into `dist/` once every check passes.

```sh
./build-dist.sh                                   # signs with "Apple Development"
HKDFGUARD_SIGN_IDENTITY="Developer ID Application: …" ./build-dist.sh
```

Needs network access (timestamp server). The hardened runtime matters: it
disables `DYLD_*` environment overrides (which can otherwise redirect which
dylib a process loads) and enforces library validation, so the CLI only
loads dylibs signed by the same Team or by Apple.

## Signing and entitlements

- The **framework** target has `com.apple.security.app-sandbox`. It does not
  declare `keychain-access-groups`: that capability is enforced against a
  process's main executable, not the frameworks it loads. It belongs on the
  app that embeds the framework.
- The **dylib** target has no entitlements, on purpose: it loads into
  arbitrary host processes.
- **Data-protection mode** requires the *consuming process* to be a
  Team-signed app bundle with an embedded provisioning profile carrying
  `keychain-access-groups` (Xcode: Signing & Capabilities → Keychain
  Sharing). A bare executable cannot carry that entitlement — AMFI kills it
  at launch — which is why bare consumers run in legacy mode.
- The project carries a specific `DEVELOPMENT_TEAM` and bundle identifiers;
  replace them with your own before building under your account.

## Concurrency

- `hkdfguard_create_kek` is safe under concurrent first use: the keychain's
  unique index on (service, account) lets exactly one creation win and the
  others load the winner's key.
- The Secure Enclave / `securityd` IPC layer has limited real concurrency.
  A handful of simultaneous enclave operations from one process is fine;
  dozens cause severe contention (observed while building the test suite,
  which runs serialized for that reason).

## Tests

Two Swift Testing suites, both `.serialized`:

- **`HkdfGuardKeyProtectionEnclaveWrapUnwrapTests`** exercises every C entry
  point in-process: provisioning, idempotence and the first-use race,
  service-name rules (ASCII bytes, case-insensitivity, length), round trips,
  payload length, nonce/ephemeral uniqueness, per-service isolation,
  fingerprint and ciphertext tamper detection, buffer sizing before any
  enclave work, NULL-pointer handling, corrupt-item reporting, and the
  keychain-mode decision (including that data-protection mode from an
  unentitled process is reported as `-17`, never as "no key").
- **`HkdfGuardCommandLineToolTests`** builds and runs the real CLI as a
  subprocess: `provision`/`wrap` semantics, DEK sources, rejected
  arguments, `--force` symlink/FIFO refusal, file permissions, exit codes.

Both need a real Secure Enclave and are skipped on CI/VM runners. The tests
that cross the CLI→application keychain boundary (a differently-signed
process reading an item the CLI created) trigger a one-time interactive
keychain prompt and are opt-in: set
`HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1` and be present to click Allow.
Every test that provisions a key deletes its keychain item afterward, so a
run leaves the keychain clean. Exercising data-protection mode end to end
needs a Team-signed host application with a provisioning profile set as
the test target's Host Application.

## Differences from the Linux tool

Deliberate divergences from `hkdfguard-v1-initialize.rs`: separate
`provision` and `wrap` commands; the key file path is `--key-file-path`,
not positional; no `--dek <base64>` argument (stdin or file only); output
file permissions `0640`.
