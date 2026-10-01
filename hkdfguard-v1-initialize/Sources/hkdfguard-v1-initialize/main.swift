// CLI tool with three commands:
//
//   provision  creates the persistent Secure Enclave KEK for a service if it
//              does not exist yet. The ONLY command that creates keys.
//              Prints the KEK's fingerprint, to be recorded by the operator.
//   wrap       wraps a Data Encryption Key (DEK) supplied by the calling
//              pipeline -- the 32-byte key that pipeline has already
//              encrypted its data with -- under an already-provisioned KEK,
//              and writes the wrapped payload to a file. Never creates a
//              KEK: if none exists for the service, it fails and points at
//              `provision`. It never generates a DEK either: the key is
//              always the pipeline's, read from stdin or a file.
//   retire     deletes a service's KEK keychain item, after the operator
//              proves which KEK they mean by supplying its fingerprint. The
//              ONLY command that deletes keys, and deliberately implemented
//              here rather than in the library: the dylib's C ABI offers no
//              delete, so no consumer that loads it gets a one-call wipe.
//              Everything wrapped under a retired KEK is permanently
//              unrecoverable -- retire only after migrating to a new service.
//
// Calls into the HkdfGuard library through its stable C ABI (`provision`:
// `hkdfguard_kek_exists`, then `hkdfguard_create_kek`; `wrap`:
// `hkdfguard_wrap_dek`), the same interface
// any other-language caller uses -- this tool takes no shortcut through
// the library's internal Swift types (it doesn't even `import` the
// library's own Swift module; see Package.swift). Modeled on this project's
// Linux equivalent
// (HkdfGuardKeyProtectionCore-Linux/src/bin/hkdfguard-v1-initialize.rs),
// with two deliberate differences: the Linux tool's `--dek <base64>`
// argument is not offered here at all (see "DEK sources" below for why),
// and the output file is written with POSIX 0640 permissions (see
// writeWrappedKeyFile).
//
// The KEK's `service` identity is exactly the caller-supplied
// `--service-name`; there is no further structure to it.
//
// Usage:
//   hkdfguard-v1-initialize provision --service-name|-sn <name>
//
//   hkdfguard-v1-initialize retire --service-name|-sn <name> \
//       --fingerprint|-fp <64 hex chars>
//
//   hkdfguard-v1-initialize wrap \
//       --key-file-path|-kf <key-file-path> \
//       --service-name|-sn <name> \
//       ( --dek-stdin | --dek-file <path> ) \
//       [--force|-f]
//
// `provision` is idempotent: a second run against the same service reports
// that the KEK already exists and exits 0.
//
// For `wrap`, exactly one DEK source is required:
//   --dek-stdin        base64 DEK read from standard input (e.g. piped from
//                      the pipeline or a secret store; trailing newline ok).
//   --dek-file <path>  base64 DEK read from a file.
//
// There is deliberately no way to pass the DEK itself as a command-line
// argument: an argv value is visible to every other process on the host
// (`ps`) for the life of the process and is recorded in the invoking
// shell's history file. Both stdin and a file avoid that entirely.
//
// The wrapped payload is written to <key-file-path> with POSIX permissions
// 0640 (owner read/write, group read, no access for anyone else) -- set
// atomically at file-creation time. With --force against a pre-existing
// file, that file's old contents are securely overwritten in place (8
// alternating all-zero/random passes) and then deleted before the new file
// is created -- see secureOverwriteAndRemoveIfExists/writeWrappedKeyFile
// below for the exact sequence and its one intentional fallback. --force
// only ever overwrites and removes a *regular file*: a symbolic link at
// <key-file-path> is refused rather than followed (so a planted link can't
// redirect the destructive overwrite onto some other file), as is a FIFO,
// device, or directory.
//
// `wrap` creates nothing but the output file, and only after every argument
// has been validated. `provision` creates nothing until its service name
// has been validated. A malformed invocation of either never leaves a
// freshly provisioned KEK behind.

import Darwin
import Foundation
import Security // SecRandomCopyBytes, used by the secure-overwrite passes below

// MARK: - Binding directly to the library's C ABI (no bridging header, no
// module import -- see Package.swift's comment on how this executable
// links). `@_silgen_name` binds this declaration straight to the exported
// symbol of that exact name in whatever this executable links against, the
// same way a C `extern` declaration would -- Swift's version of "trust me,
// this symbol exists with this signature," used here so this tool is
// provably calling the real C ABI and nothing library-internal.
@_silgen_name("hkdfguard_wrap_dek")
func hkdfguard_wrap_dek(
    _ service: UnsafePointer<CChar>?,
    _ dek: UnsafePointer<UInt8>?,
    _ dekLen: Int32,
    _ out: UnsafeMutablePointer<UInt8>?,
    _ outLen: UnsafeMutablePointer<Int32>?
) -> Int32

// The library's wrap calls never create a KEK. These two are used only by
// the `provision` command (see `provisionKEK` below): ask whether one
// exists, and create it only if the answer is a definite "no".
@_silgen_name("hkdfguard_kek_exists")
func hkdfguard_kek_exists(_ service: UnsafePointer<CChar>?, _ outExists: UnsafeMutablePointer<Int32>?) -> Int32

@_silgen_name("hkdfguard_create_kek")
func hkdfguard_create_kek(_ service: UnsafePointer<CChar>?) -> Int32

// Read-only: the KEK's public-key fingerprint. Printed by `provision`,
// checked by `retire`.
@_silgen_name("hkdfguard_kek_fingerprint")
func hkdfguard_kek_fingerprint(
    _ service: UnsafePointer<CChar>?,
    _ out: UnsafeMutablePointer<UInt8>?,
    _ outLen: UnsafeMutablePointer<Int32>?
) -> Int32

// Which keychain this process's KEK items live in (0 legacy, 1
// data-protection) -- decided by the library from this executable's own
// code-signing entitlements. Printed by both commands because a service's
// provisioner and its consumers must agree on it; see the header.
@_silgen_name("hkdfguard_keychain_mode")
func hkdfguard_keychain_mode(_ outMode: UnsafeMutablePointer<Int32>?) -> Int32

func keychainModeName() -> String {
    var mode: Int32 = -1
    _ = hkdfguard_keychain_mode(&mode)
    switch mode {
    case 0: return "legacy"
    case 1: return "data-protection"
    default: return "unknown(\(mode))"
    }
}

// Mirrors HKDFGuardStatus in HkdfGuardKeyProtectionEnclave.swift -- kept as
// a separate, parallel definition rather than importing that module, for
// the same "go through the C ABI only" reason as the `@_silgen_name`
// declaration above; the raw integer values are the actual contract, this
// enum just makes them readable here.
enum HKDFGuardStatus: Int32 {
    case success = 0
    case invalidInputLength = -1
    case outputBufferTooSmall = -2
    case keyUnavailable = -3 // reserved; no longer returned by the library -- see -10 and lower
    case publicKeyUnavailable = -4
    case encryptionFailed = -5
    case decryptionFailed = -6
    case unexpectedOutputLength = -7
    case invalidServiceIdentifier = -8
    case enclaveUnavailable = -9
    case kekNotFound = -10
    case kekCorrupted = -11
    case accessControlCreationFailed = -12
    case keyGenerationFailed = -13
    case keychainWriteFailed = -14
    case kekVerificationFailed = -15
    case fingerprintMismatch = -16
    case keychainAccessDenied = -17
    case keychainReadFailed = -18

    var description: String {
        switch self {
        case .success: return "success"
        case .invalidInputLength: return "invalid argument (bad service name or DEK length)"
        case .outputBufferTooSmall: return "output buffer too small"
        case .keyUnavailable: return "the Secure Enclave key could not be obtained"
        case .publicKeyUnavailable: return "the KEK's public key is unavailable"
        case .encryptionFailed: return "a cryptographic operation failed"
        case .decryptionFailed: return "decryption failed"
        case .unexpectedOutputLength: return "the library produced an unexpected output length"
        case .invalidServiceIdentifier: return "the service name is missing, empty, longer than 128 characters, or contains a character other than an ASCII letter, digit, or '.'"
        case .enclaveUnavailable: return "the Secure Enclave is not available on this machine"
        case .kekNotFound: return "no key exists yet for this service -- call hkdfguard_create_kek first"
        case .kekCorrupted: return "a keychain item exists for this service but could not be reconstructed into a usable key"
        case .accessControlCreationFailed: return "failed to set up access control for a new key"
        case .keyGenerationFailed: return "the Secure Enclave refused to generate a new key"
        case .keychainWriteFailed: return "failed to persist the newly generated key to the keychain"
        case .kekVerificationFailed: return "the newly created key could not be verified after being stored"
        case .fingerprintMismatch: return "the wrapped payload's embedded KEK fingerprint does not match the current key"
        case .keychainAccessDenied: return "the keychain denied access (locked, no UI session, access prompt declined, or missing entitlement) -- a key for this service may already exist"
        case .keychainReadFailed: return "reading the keychain failed"
        }
    }
}

func describeStatus(_ code: Int32) -> String {
    if let status = HKDFGuardStatus(rawValue: code) {
        return status.description
    }
    return "unknown status code \(code)"
}

// MARK: - Argument parsing

let programName = "hkdfguard-v1-initialize"
let dekLen = 32
// Generous starting capacity for the wrapped payload -- retried once at
// the library-reported size on outputBufferTooSmall, so this only needs to
// be a reasonable common case, not an absolute upper bound. Matches the
// Linux tool's own INITIAL_WRAPPED_CAPACITY.
let initialWrappedCapacity = 512

// Where the DEK comes from. Exactly one must be given (see parseArgs).
enum DekSource {
    case stdin               // --dek-stdin
    case file(String)        // --dek-file <path>

    var flag: String {
        switch self {
        case .stdin: return "--dek-stdin"
        case .file: return "--dek-file"
        }
    }
}

struct ProvisionArgs {
    var serviceName: String
}

struct WrapArgs {
    var keyFilePath: String
    var serviceName: String
    var dekSource: DekSource
    var force: Bool
}

struct RetireArgs {
    var serviceName: String
    var fingerprint: [UInt8]
}

enum Command {
    case provision(ProvisionArgs)
    case wrap(WrapArgs)
    case retire(RetireArgs)
    case help
}

let dekSourceFlags = "--dek-stdin | --dek-file <path>"

func printUsage() {
    FileHandle.standardError.write(
        """
        Usage:
          \(programName) provision --service-name|-sn <name>
          \(programName) wrap --key-file-path|-kf <path> --service-name|-sn <name> \\
                                    ( \(dekSourceFlags) ) [--force|-f]
          \(programName) retire --service-name|-sn <name> --fingerprint|-fp <hex>

        Commands:
          provision   create the Secure Enclave KEK for <name> if it does not exist yet.
                      The only command that creates keys; safe to run repeatedly.
                      Prints the KEK's fingerprint -- record it.
          wrap        wrap the pipeline's 32-byte DEK under the already-provisioned KEK
                      for <name> and write the wrapped payload to <path>. Never creates
                      a KEK -- fails if none exists for <name> (run provision first).
          retire      delete the KEK for <name>, only if its fingerprint matches <hex>
                      (64 hex characters, as printed by provision). The only command
                      that deletes keys. Everything wrapped under that KEK becomes
                      permanently unrecoverable: migrate to a new service name first.

        wrap options (exactly one DEK source is required):
          --key-file-path|-kf <path>  where to write the wrapped payload
          --dek-stdin         read the base64 DEK from standard input
          --dek-file <path>   read the base64 DEK from a file
          --force|-f          securely overwrite an existing <path>

        The DEK is never accepted as a command-line argument (it would be visible
        to other processes via ps and recorded in shell history).

        """.data(using: .utf8)!
    )
}

// `--service-name|-sn <name>`, shared by both commands' parsers.
func parseServiceName(_ arg: String, _ iterator: inout IndexingIterator<[String]>) throws -> String {
    guard let value = iterator.next() else {
        throw CLIError("\(arg) requires a value")
    }
    guard !value.isEmpty else {
        throw CLIError("--service-name must not be empty")
    }
    return value
}

func parseArgs(_ arguments: [String]) throws -> Command {
    var rest = Array(arguments.dropFirst()) // skip argv[0]
    guard !rest.isEmpty else {
        throw CLIError("missing command: expected provision or wrap")
    }
    let command = rest.removeFirst()
    switch command {
    case "--help", "-h":
        return .help
    case "provision":
        return try parseProvision(rest)
    case "wrap":
        return try parseWrap(rest)
    case "retire":
        return try parseRetire(rest)
    default:
        throw CLIError("unknown command \"\(command)\": expected provision, wrap, or retire")
    }
}

func parseRetire(_ arguments: [String]) throws -> Command {
    var serviceName: String?
    var fingerprint: [UInt8]?

    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--service-name", "-sn":
            serviceName = try parseServiceName(arg, &iterator)
        case "--fingerprint", "-fp":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a value")
            }
            fingerprint = try parseFingerprintHex(value)
        default:
            throw CLIError("retire: unrecognized argument: \(arg)")
        }
    }

    guard let serviceName else { throw CLIError("retire: missing required --service-name|-sn") }
    guard let fingerprint else {
        throw CLIError("retire: missing required --fingerprint|-fp (the 64-hex-character value printed by provision)")
    }
    return .retire(RetireArgs(serviceName: serviceName, fingerprint: fingerprint))
}

let fingerprintLength = 32

// Exactly 64 hex digits, either case. No separators or prefixes: the value
// is meant to be pasted from provision's output, and a strict format keeps
// a truncated paste from ever looking valid.
func parseFingerprintHex(_ text: String) throws -> [UInt8] {
    let digits = Array(text.utf8)
    guard digits.count == fingerprintLength * 2 else {
        throw CLIError("--fingerprint must be exactly \(fingerprintLength * 2) hex characters, got \(digits.count)")
    }
    func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x41 + 10
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }
    var bytes = [UInt8]()
    bytes.reserveCapacity(fingerprintLength)
    for i in stride(from: 0, to: digits.count, by: 2) {
        guard let hi = nibble(digits[i]), let lo = nibble(digits[i + 1]) else {
            throw CLIError("--fingerprint must contain only hex characters (0-9, a-f)")
        }
        bytes.append(hi << 4 | lo)
    }
    return bytes
}

func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func parseProvision(_ arguments: [String]) throws -> Command {
    var serviceName: String?

    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--service-name", "-sn":
            serviceName = try parseServiceName(arg, &iterator)
        default:
            throw CLIError("provision: unrecognized argument: \(arg)")
        }
    }

    guard let serviceName else { throw CLIError("provision: missing required --service-name|-sn") }
    return .provision(ProvisionArgs(serviceName: serviceName))
}

func parseWrap(_ arguments: [String]) throws -> Command {
    var keyFilePath: String?
    var serviceName: String?
    var dekSources: [DekSource] = []
    var force = false

    var iterator = arguments.makeIterator()
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--force", "-f":
            force = true
        case "--key-file-path", "-kf":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a path")
            }
            keyFilePath = value
        case "--service-name", "-sn":
            serviceName = try parseServiceName(arg, &iterator)
        case "--generate", "-g":
            // This tool only wraps a DEK the calling pipeline already has --
            // the key its data was encrypted with. Generating one here
            // would produce a key nothing has used.
            throw CLIError("\(arg) is not supported: this tool wraps the pipeline's existing DEK; supply it with \(dekSourceFlags)")
        case "--dek-stdin":
            dekSources.append(.stdin)
        case "--dek-file":
            guard let value = iterator.next(), !value.isEmpty else {
                throw CLIError("\(arg) requires a path")
            }
            dekSources.append(.file(value))
        case "--dek", "-d":
            // Rejected explicitly, with the reason, rather than falling
            // through to a generic "unrecognized argument" -- anyone
            // reaching for the Linux tool's flag should learn why it isn't
            // here and what to use instead.
            throw CLIError("\(arg) is not supported: a DEK on the command line is visible via ps and recorded in shell history; use \(dekSourceFlags)")
        default:
            if !arg.hasPrefix("-") {
                // The key file path used to be positional; say so rather
                // than leaving the caller to guess what went wrong.
                throw CLIError("wrap: unexpected argument \"\(arg)\" -- the key file path is given with --key-file-path|-kf <path>")
            }
            throw CLIError("wrap: unrecognized argument: \(arg)")
        }
    }

    guard let keyFilePath else { throw CLIError("wrap: missing required --key-file-path|-kf") }
    guard let serviceName else { throw CLIError("wrap: missing required --service-name|-sn") }
    guard !dekSources.isEmpty else {
        throw CLIError("wrap: missing required DEK source: one of \(dekSourceFlags)")
    }
    guard dekSources.count == 1 else {
        throw CLIError("wrap: conflicting DEK sources (\(dekSources.map(\.flag).joined(separator: ", "))): give exactly one of \(dekSourceFlags)")
    }

    return .wrap(
        WrapArgs(
            keyFilePath: keyFilePath,
            serviceName: serviceName,
            dekSource: dekSources[0],
            force: force
        )
    )
}

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// Maximum length, in bytes, the library accepts for a service name (see
// `validServiceName` in HkdfGuardKeyProtectionEnclave.swift). Checked here
// too so an over-length name fails fast with a clear message instead of
// making a wasted round trip through hkdfguard_create_kek/hkdfguard_wrap_dek
// just to get the same rejection back as an opaque status code.
let maxServiceNameLength = 128

// Enforces the exact same rule the library itself applies to `service` (see
// `validServiceName` in HkdfGuardKeyProtectionEnclave.swift): 1-128 ASCII
// alphanumeric characters or '.', matching this project's Linux/Windows
// tools.
func validateServiceCharset(_ service: String) throws {
    guard service.utf8.count <= maxServiceNameLength else {
        throw CLIError("service name \"\(service)\" must be at most \(maxServiceNameLength) characters, got \(service.utf8.count)")
    }
    let isValid = service.utf8.allSatisfy { byte in
        (byte >= 0x30 && byte <= 0x39) // '0'-'9'
            || (byte >= 0x41 && byte <= 0x5A) // 'A'-'Z'
            || (byte >= 0x61 && byte <= 0x7A) // 'a'-'z'
            || byte == 0x2E // '.'
    }
    guard isValid else {
        throw CLIError("service name \"\(service)\" must contain only alphanumeric characters or '.'")
    }
}

// MARK: - KEK provisioning (the `provision` command only)

// Creates the KEK for `service` if none exists; returns true if one was
// created, false if one already existed. hkdfguard_kek_exists first,
// hkdfguard_create_kek only on a definite "no key yet". Anything other than
// a clean yes/no from the exists check -- keychainAccessDenied,
// keychainReadFailed, kekCorrupted, enclaveUnavailable -- stops here with
// that specific reason, rather than falling through to a create attempt
// whose failure would be reported against the wrong step.
//
// This is the only place in the tool that calls either function: `wrap`
// never checks for or creates a KEK.
func provisionKEK(service: String) throws -> Bool {
    var exists: Int32 = 0
    let existsStatus = service.withCString { hkdfguard_kek_exists($0, &exists) }
    guard existsStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_kek_exists failed: \(describeStatus(existsStatus))")
    }
    if exists != 0 {
        return false
    }

    let createStatus = service.withCString { hkdfguard_create_kek($0) }
    guard createStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_create_kek failed: \(describeStatus(createStatus))")
    }
    return true
}

// The fingerprint of the KEK `service` resolves to, or the library's status
// code when it can't be read (kekNotFound, keychainAccessDenied, ...).
func readKekFingerprint(service: String) -> (status: Int32, fingerprint: [UInt8]) {
    var out = [UInt8](repeating: 0, count: fingerprintLength)
    var outLen = Int32(fingerprintLength)
    let status = service.withCString { servicePtr in
        out.withUnsafeMutableBufferPointer { buf in
            hkdfguard_kek_fingerprint(servicePtr, buf.baseAddress, &outLen)
        }
    }
    return (status, Array(out.prefix(Int(max(outLen, 0)))))
}

// MARK: - KEK retirement (the `retire` command only)

// Must equal `hkdfguardKeychainAccount` in HkdfGuardKeyProtectionEnclave.swift.
// Duplicated rather than exported: the library's C ABI deliberately has no
// way to address its keychain items directly.
let kekKeychainAccount = "kek-v1"

// The first non-empty `keychain-access-groups` entry this executable is
// signed with -- the same rule the library's detectKeychainMode applies.
func entitledAccessGroup() -> String? {
    guard let task = SecTaskCreateFromSelf(nil),
          let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil),
          let groups = value as? [String] else {
        return nil
    }
    return groups.first(where: { !$0.isEmpty })
}

// The query identifying `service`'s KEK item -- mirroring the library's
// keychainItemAttributes, including an explicit kSecUseDataProtectionKeychain
// in both modes (an omitted key can resolve to the data-protection keychain
// on current SDKs). The library's own mode decision and this executable's
// entitlements must agree; if they don't, something is wrong with the build
// and nothing is deleted.
func kekItemQuery(service: String) throws -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: kekKeychainAccount,
        kSecAttrSynchronizable as String: false,
    ]
    var libraryMode: Int32 = -1
    _ = hkdfguard_keychain_mode(&libraryMode)
    switch (libraryMode, entitledAccessGroup()) {
    case (0, nil):
        query[kSecUseDataProtectionKeychain as String] = false
    case (1, let group?):
        query[kSecUseDataProtectionKeychain as String] = true
        query[kSecAttrAccessGroup as String] = group
    default:
        throw CLIError("the library reports keychain mode \(libraryMode), which does not match this executable's keychain entitlements; refusing to delete anything")
    }
    return query
}

func describeOSStatus(_ status: OSStatus) -> String {
    if let message = SecCopyErrorMessageString(status, nil) as String? {
        return "\(message) (OSStatus \(status))"
    }
    return "OSStatus \(status)"
}

// Deletes `service`'s KEK item only if the KEK it currently holds has the
// fingerprint the operator supplied. A KEK that can't be read -- access
// denied, corrupt, read failure -- is never deleted: the fingerprint check
// is the confirmation, and without it there is nothing to confirm against.
func retireKEK(service: String, expectedFingerprint: [UInt8]) throws {
    let (status, current) = readKekFingerprint(service: service)
    switch status {
    case HKDFGuardStatus.success.rawValue:
        break
    case HKDFGuardStatus.kekNotFound.rawValue:
        throw CLIError("no KEK exists for service \"\(service)\" (keychain: \(keychainModeName())); nothing to retire")
    default:
        throw CLIError("cannot read the KEK fingerprint for service \"\(service)\": \(describeStatus(status)); refusing to retire a KEK that cannot be confirmed")
    }
    guard current == expectedFingerprint else {
        throw CLIError("fingerprint mismatch for service \"\(service)\": the current KEK is \(hexString(current)), not \(hexString(expectedFingerprint)); nothing was deleted")
    }

    let deleteStatus = SecItemDelete(try kekItemQuery(service: service) as CFDictionary)
    guard deleteStatus == errSecSuccess else {
        throw CLIError("deleting the KEK for service \"\(service)\" failed: \(describeOSStatus(deleteStatus))")
    }

    // Confirm through the library, the same lookup every consumer uses.
    var exists: Int32 = -1
    let existsStatus = service.withCString { hkdfguard_kek_exists($0, &exists) }
    guard existsStatus == HKDFGuardStatus.success.rawValue, exists == 0 else {
        throw CLIError("the KEK for service \"\(service)\" was deleted but the library still reports one (status: \(describeStatus(existsStatus))); investigate before relying on it being gone")
    }
}

// MARK: - Wrap

// Calls `attempt` with an output buffer of initialWrappedCapacity and, if
// the library answers outputBufferTooSmall (having written the size it
// actually needs into the length out-parameter), retries exactly once at
// that size -- same pattern as the Linux tool's `wrap_dek`.
func callWithWrappedBuffer(
    _ functionName: String,
    service: String,
    _ attempt: (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<Int32>?) -> Int32
) throws -> [UInt8] {
    var wrapped = [UInt8](repeating: 0, count: initialWrappedCapacity)
    var wrappedLen = Int32(wrapped.count)

    var rc = wrapped.withUnsafeMutableBufferPointer { buf in
        attempt(buf.baseAddress, &wrappedLen)
    }
    if rc == HKDFGuardStatus.outputBufferTooSmall.rawValue {
        wrapped = [UInt8](repeating: 0, count: Int(wrappedLen))
        rc = wrapped.withUnsafeMutableBufferPointer { buf in
            attempt(buf.baseAddress, &wrappedLen)
        }
    }

    guard rc == HKDFGuardStatus.success.rawValue else {
        if rc == HKDFGuardStatus.kekNotFound.rawValue {
            // `wrap` never provisions; point at the command that does.
            throw CLIError("no KEK exists for service \"\(service)\"; run `\(programName) provision --service-name \(service)` first")
        }
        throw CLIError("\(functionName) failed: \(describeStatus(rc))")
    }

    return Array(wrapped.prefix(Int(wrappedLen)))
}

// Wraps a caller-supplied DEK. Takes `dek` as `Data` rather than `[UInt8]`
// so the caller's already-tightly-scoped, zero-on-exit buffer (see `run`
// below) is the only copy of the plaintext DEK that ever exists --
// converting to `[UInt8]` first would leave a second, unzeroed copy sitting
// in memory for the rest of the process's life.
func wrapDek(service: String, dek: Data) throws -> [UInt8] {
    try callWithWrappedBuffer("hkdfguard_wrap_dek", service: service) { outPtr, outLen in
        service.withCString { servicePtr in
            dek.withUnsafeBytes { dekBuf in
                hkdfguard_wrap_dek(
                    servicePtr,
                    dekBuf.bindMemory(to: UInt8.self).baseAddress,
                    Int32(dek.count),
                    outPtr,
                    outLen
                )
            }
        }
    }
}

// MARK: - Reading the pipeline's DEK

// Returns the base64 text for a DEK source.
func readSuppliedDekBase64(_ source: DekSource) throws -> String {
    switch source {
    case .stdin:
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8) else {
            throw CLIError("--dek-stdin: standard input is not valid UTF-8 text")
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw CLIError("--dek-stdin: no data on standard input")
        }
        return trimmed

    case .file(let path):
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            throw CLIError("--dek-file: failed to read \(path): \(error.localizedDescription)")
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw CLIError("--dek-file: \(path) is not valid UTF-8 text")
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw CLIError("--dek-file: \(path) is empty")
        }
        return trimmed
    }
}

// MARK: - Writing the wrapped key file

// The permissions every wrapped-key file is written with: owner
// read/write, group read, no access for anyone else (POSIX 0640).
let keyFilePermissions: mode_t = 0o640

// Number of secure-overwrite passes secureOverwriteAndRemoveIfExists below
// performs on a pre-existing file before deleting it, alternating an
// all-zero pass and a random-bytes pass, four times each (zero, random,
// zero, random, zero, random, zero, random).
let secureOverwritePassCount = 8

// Writes all of `bytes` to `fd` at its current file offset, looping in
// case a single `write(2)` call returns short (POSIX permits this even for
// a regular file, though it's rare in practice for the small writes this
// tool ever does). Shared by both the secure-overwrite passes below and
// the final real write, so there's exactly one "loop until everything is
// written, or throw" implementation.
func writeAll(fd: Int32, bytes: UnsafeBufferPointer<UInt8>, context: String) throws {
    var offset = 0
    while offset < bytes.count {
        let n = write(fd, bytes.baseAddress! + offset, bytes.count - offset)
        if n < 0 {
            throw CLIError("failed to write \(context): \(String(cString: strerror(errno)))")
        }
        offset += n
    }
}

// Before a --force overwrite is allowed to destroy an existing wrapped-key
// file, this overwrites its *current* contents in place --
// secureOverwritePassCount (8) alternating all-zero/random passes, each
// flushed to the storage medium before the next pass starts so they're
// genuinely sequential rather than coalesced by the page cache -- and only
// then deletes it. Only ever called when --force was passed; without
// --force, an existing file is never touched at all (writeWrappedKeyFile's
// plain O_EXCL create fails outright instead).
//
// If the file doesn't exist, this is a no-op. If it exists but can't be
// opened for writing (EACCES/EPERM -- this tool doesn't own it), the
// overwrite passes are skipped entirely and this falls back to a plain
// `unlink`, per explicit product direction: destroying the old bytes first
// is worth attempting, but not worth failing the whole command over when
// this process isn't even allowed to write to the file it's about to
// replace. That fallback still refuses anything that isn't a regular file.
//
// Only a regular file is ever written to or removed. The open uses
// O_NOFOLLOW, so a symbolic link at `path` fails with ELOOP and is refused
// outright rather than followed -- without it, a link planted at
// <key-file-path> (trivial in a shared or world-writable directory) would
// redirect the eight destructive passes onto whatever file it points at,
// after which `unlink` would remove only the link. O_NONBLOCK keeps an
// open on a reader-less FIFO from blocking forever, and the fstat check
// after open rejects a FIFO, device node, or directory before a single
// byte is written (a device node opened for writing by a privileged
// invocation would otherwise be overwritten).
//
// Caveat this can't fully solve, worth knowing rather than assuming away:
// on copy-on-write/log-structured filesystems (e.g. APFS) and on SSDs
// generally (wear leveling), writing new bytes to a file's logical offsets
// does not guarantee those bytes land on the same physical storage cells
// the old bytes occupied -- the old bytes can persist in already-copied-
// away or already-remapped blocks until the medium itself reclaims them.
// This is a best-effort measure against casual recovery (e.g. `strings` on
// the raw device, a filesystem-level undelete), not a cryptographic
// guarantee against a determined attacker with access to the raw flash.
func requireRegularFile(mode: mode_t, path: String) throws {
    switch mode & S_IFMT {
    case S_IFREG:
        return
    case S_IFLNK:
        throw CLIError("\(path) is a symbolic link; refusing to overwrite through it -- remove the link, or point <key-file-path> at a regular file")
    default:
        throw CLIError("\(path) is not a regular file; refusing to overwrite or remove it")
    }
}

// Fail-fast twin of the checks secureOverwriteAndRemoveIfExists enforces at
// open time: with --force, refuse before any Secure Enclave or keychain
// work if <key-file-path> exists and is a symlink or anything other than a
// regular file. `lstat`, not `stat`, so a symlink is judged as itself, not
// as its target. Advisory only -- the path can change between here and the
// open -- the O_NOFOLLOW/fstat checks at open time are the guarantee.
func refuseUnlessAbsentOrRegularFile(path: String) throws {
    var st = stat()
    guard lstat(path, &st) == 0 else {
        if errno == ENOENT {
            return
        }
        throw CLIError("failed to stat \(path): \(String(cString: strerror(errno)))")
    }
    try requireRegularFile(mode: st.st_mode, path: path)
}

func secureOverwriteAndRemoveIfExists(path: String) throws {
    let fd = open(path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else {
        let err = errno
        if err == ENOENT {
            return // nothing to overwrite or delete
        }
        if err == ELOOP {
            throw CLIError("\(path) is a symbolic link; refusing to overwrite through it -- remove the link, or point <key-file-path> at a regular file")
        }
        if err == EACCES || err == EPERM {
            // Can't write to it -- skip the overwrite passes and go
            // straight to trying to remove it, but still only if it is a
            // regular file.
            var st = stat()
            if lstat(path, &st) == 0 {
                try requireRegularFile(mode: st.st_mode, path: path)
            }
            if unlink(path) != 0 && errno != ENOENT {
                throw CLIError("failed to remove \(path): \(String(cString: strerror(errno)))")
            }
            return
        }
        throw CLIError("failed to open \(path) for secure overwrite: \(String(cString: strerror(err)))")
    }
    // Every path out of this function from here on must still close `fd`
    // and, on success, `unlink` the file -- rather than duplicating that in
    // every throw site below, the passes loop below propagates failures by
    // `throw`ing out of this function entirely with `fd` closed via
    // `defer`, and the unlink happens once, after the loop, on the
    // fall-through success path.
    defer { close(fd) }

    var st = stat()
    guard fstat(fd, &st) == 0 else {
        throw CLIError("failed to stat \(path): \(String(cString: strerror(errno)))")
    }
    // Checked on the opened descriptor, so it can't be raced by swapping
    // the path out between a separate stat and this open.
    try requireRegularFile(mode: st.st_mode, path: path)
    let fileSize = Int(st.st_size)

    if fileSize > 0 {
        var buffer = [UInt8](repeating: 0, count: fileSize)
        // Scrub our own in-memory copy of whatever the last pass's buffer
        // contents were (all-zero on an even-numbered final pass, random
        // otherwise -- either way, not meant to linger) once the loop
        // below is done with it, on every exit path.
        defer {
            _ = buffer.withUnsafeMutableBytes { raw in
                raw.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        for pass in 0..<secureOverwritePassCount {
            if pass % 2 == 0 {
                for i in 0..<fileSize { buffer[i] = 0 } // "step 1": all-zero
            } else {
                // "step 2": random bits, via the OS CSPRNG -- same
                // security bar as every other random value this project
                // generates (nonces, ephemeral keys), not a plain PRNG.
                let status = buffer.withUnsafeMutableBytes { raw in
                    SecRandomCopyBytes(kSecRandomDefault, raw.count, raw.baseAddress!)
                }
                guard status == errSecSuccess else {
                    throw CLIError("failed to generate random bytes for secure-overwrite pass \(pass + 1) of \(path)")
                }
            }

            guard lseek(fd, 0, SEEK_SET) == 0 else {
                throw CLIError("failed to seek \(path) during secure-overwrite pass \(pass + 1): \(String(cString: strerror(errno)))")
            }
            try buffer.withUnsafeBufferPointer { buf in
                try writeAll(fd: fd, bytes: buf, context: "\(path) (secure-overwrite pass \(pass + 1))")
            }
            guard fsync(fd) == 0 else {
                throw CLIError("failed to flush \(path) during secure-overwrite pass \(pass + 1): \(String(cString: strerror(errno)))")
            }
        }
    }

    guard unlink(path) == 0 else {
        throw CLIError("failed to remove \(path) after secure overwrite: \(String(cString: strerror(errno)))")
    }
}

// Opens `path` and writes `bytes` to it with `keyFilePermissions`, using
// raw POSIX `open(2)` rather than `Data.write(to:options:.atomic)` for two
// reasons at once:
//
// 1. Atomicity of the exists-check: plain `O_EXCL` create (used whenever
//    `path` doesn't already exist, which -- when `force` is true -- is
//    always true by the time we get here, since secureOverwriteAndRemoveIfExists
//    above has already deleted it) makes "does this file already exist"
//    and "create it" one indivisible kernel operation. The friendly
//    pre-check in `run` below (`FileManager.fileExists`) can still race
//    against another process creating the same path in between that check
//    and this call -- this is what actually closes that race, by failing
//    here instead of silently overwriting.
// 2. Permissions from birth: `open`'s `mode` argument sets the file's
//    permissions at the moment it's created, so there's no window where
//    the file briefly exists with broader (e.g. default-umask) permissions
//    before being locked down after the fact.
//
// `fchmod` after open is defense-in-depth on top of (2), not strictly
// required by this function's own logic (by the time it's called, `path`
// is always either brand new or was just deleted above) -- kept anyway
// since it costs nothing and matches this project's general "don't rely on
// a single mechanism for a security property" style.
func writeWrappedKeyFile(path: String, bytes: [UInt8], force: Bool) throws {
    if force {
        try secureOverwriteAndRemoveIfExists(path: path)
    }

    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, keyFilePermissions)
    guard fd >= 0 else {
        let err = errno
        if err == EEXIST {
            throw CLIError("\(path) already exists; pass --force|-f to overwrite")
        }
        throw CLIError("failed to open \(path) for writing: \(String(cString: strerror(err)))")
    }
    defer { close(fd) }

    guard fchmod(fd, keyFilePermissions) == 0 else {
        throw CLIError("failed to set permissions on \(path): \(String(cString: strerror(errno)))")
    }

    try bytes.withUnsafeBufferPointer { buf in
        try writeAll(fd: fd, bytes: buf, context: path)
    }
}

// MARK: - Run

func runProvision(_ args: ProvisionArgs) throws {
    try validateServiceCharset(args.serviceName)
    let created = try provisionKEK(service: args.serviceName)
    let (status, fingerprint) = readKekFingerprint(service: args.serviceName)
    guard status == HKDFGuardStatus.success.rawValue else {
        throw CLIError("the KEK for service \"\(args.serviceName)\" exists but its fingerprint could not be read: \(describeStatus(status))")
    }
    if created {
        print("provisioned KEK for service \"\(args.serviceName)\" (keychain: \(keychainModeName()))")
        print("fingerprint: \(hexString(fingerprint)) -- record this; retire requires it")
    } else {
        // A KEK this operator didn't create could have been planted by another
        // process; the fingerprint is how to tell.
        print("KEK already exists for service \"\(args.serviceName)\" (keychain: \(keychainModeName())); nothing to do")
        print("fingerprint: \(hexString(fingerprint)) -- confirm it matches the one recorded when this service was provisioned")
    }
}

func runRetire(_ args: RetireArgs) throws {
    try validateServiceCharset(args.serviceName)
    // Validated as ASCII above, so this is the exact form the library stores.
    let service = args.serviceName.lowercased()
    try retireKEK(service: service, expectedFingerprint: args.fingerprint)
    print("retired KEK for service \"\(service)\" (fingerprint \(hexString(args.fingerprint)), keychain: \(keychainModeName()))")
    print("every payload wrapped under it is now permanently unrecoverable")
}

func runWrap(_ args: WrapArgs) throws {
    // Fast, friendly pre-check: fail before ever touching the Secure
    // Enclave/Keychain if the output path obviously already exists,
    // rather than making the caller pay for a full wrap operation just to
    // find out at the very end. writeWrappedKeyFile's O_EXCL is the actual
    // correctness guarantee against the exists-then-create race; this is
    // purely a fail-fast convenience on top of it.
    if !args.force && FileManager.default.fileExists(atPath: args.keyFilePath) {
        throw CLIError("\(args.keyFilePath) already exists; pass --force|-f to overwrite")
    }
    // Same fail-fast idea for --force: a symlink or non-regular file at the
    // path will be refused by the overwrite step anyway; refusing it here
    // first means no Secure Enclave/keychain work is spent on a command
    // that cannot complete.
    if args.force {
        try refuseUnlessAbsentOrRegularFile(path: args.keyFilePath)
    }

    // `args.serviceName` is not secret -- it's a logical identifier, not key
    // material -- so no special scoping is needed for it. Validated before
    // any DEK is read.
    try validateServiceCharset(args.serviceName)

    // `wrap` never checks for or creates a KEK -- hkdfguard_kek_exists and
    // hkdfguard_create_kek belong to the `provision` command alone. With no
    // KEK for this service hkdfguard_wrap_dek fails with kekNotFound before
    // touching anything, which callWithWrappedBuffer reports as "run
    // provision first".
    let wrapped: [UInt8]
    do {
        var base64Text = try readSuppliedDekBase64(args.dekSource)
        guard var dekData = Data(base64Encoded: base64Text) else {
            throw CLIError("\(args.dekSource.flag): the DEK is not valid base64")
        }

        // The base64 *text* has now served its only purpose: drop this
        // process's owned reference to it right here. Unlike the decoded
        // DEK *bytes* below, Swift's String has no supported API for
        // in-place zeroing -- reassigning to an empty literal drops the
        // only strong reference so the buffer becomes eligible for
        // deallocation at the earliest opportunity, which is the best
        // this language allows, not a guaranteed wipe the way
        // SecureZeroMemory/Zeroizing are on this project's Windows/Linux
        // tools.
        base64Text = ""

        // Scrub our local copy of the decoded DEK bytes the instant this
        // block ends, on every exit path -- immediately after wrapDek is
        // done with it, not at the end of runWrap() (which would otherwise
        // leave it sitting in memory, unused but unwiped, through the
        // potentially-slow 8-pass secure-overwrite and the final file
        // write below).
        defer {
            _ = dekData.withUnsafeMutableBytes { raw in
                raw.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        guard dekData.count == dekLen else {
            throw CLIError("\(args.dekSource.flag): the DEK must decode to exactly \(dekLen) bytes, got \(dekData.count)")
        }

        wrapped = try wrapDek(service: args.serviceName, dek: dekData)
        // the `defer` above zeroes `dekData` here, as this scope ends --
        // immediately after wrapDek returns the wrapped (encrypted, no
        // longer secret) form, which is the only thing that survives
        // past this point.
    }

    try writeWrappedKeyFile(path: args.keyFilePath, bytes: wrapped, force: args.force)

    print("wrapped key written to \(args.keyFilePath) (\(wrapped.count) bytes, permissions 0640, service \"\(args.serviceName)\", keychain: \(keychainModeName()))")
}

// MARK: - Entry point

// Runs a command body; a runtime failure prints the error and exits 1 --
// distinct from an argument-parsing failure (exit 2) below, matching the
// Linux tool's own exit-code convention.
func runOrExit(_ body: () throws -> Void) -> Never {
    do {
        try body()
        exit(0)
    } catch {
        FileHandle.standardError.write("error: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

do {
    switch try parseArgs(CommandLine.arguments) {
    case .help:
        printUsage()
        exit(0)
    case .provision(let args):
        runOrExit { try runProvision(args) }
    case .wrap(let args):
        runOrExit { try runWrap(args) }
    case .retire(let args):
        runOrExit { try runRetire(args) }
    }
} catch {
    // An argument-parsing failure: print the error and usage, then exit 2.
    FileHandle.standardError.write("error: \(error)\n".data(using: .utf8)!)
    printUsage()
    exit(2)
}
