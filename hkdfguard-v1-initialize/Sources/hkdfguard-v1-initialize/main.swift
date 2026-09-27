// CLI tool: ensures a persistent KEK exists for the given service, then
// wraps a caller-supplied Data Encryption Key (DEK) under it and writes
// the wrapped payload to a file.
//
// Calls into the HkdfGuard library through its stable C ABI
// (`hkdfguard_create_kek`, then `hkdfguard_wrap_dek`), the same interface
// any other-language caller uses -- this tool takes no shortcut through
// the library's internal Swift types (it doesn't even `import` the
// library's own Swift module; see Package.swift). Mirrors this project's
// Linux equivalent
// (HkdfGuardKeyProtectionCore-Linux/src/bin/hkdfguard-v1-initialize.rs)
// argument-for-argument; see writeWrappedKeyFile below for one behavior
// difference (POSIX 0640 permissions on the output file), specific to this
// platform for now.
//
// The KEK's `service` identity is exactly the caller-supplied
// `--service-name`; there is no further structure to it.
//
// Usage:
//   hkdfguard-v1-initialize <key-file-path> \
//       --service-name|-sn <name> \
//       --dek|-d <base64> \
//       [--force|-f]
//
// The wrapped payload is written to <key-file-path> with POSIX permissions
// 0640 (owner read/write, group read, no access for anyone else) -- set
// atomically at file-creation time. With --force against a pre-existing
// file, that file's old contents are securely overwritten in place (8
// alternating all-zero/random passes) and then deleted before the new file
// is created -- see secureOverwriteAndRemoveIfExists/writeWrappedKeyFile
// below for the exact sequence and its one intentional fallback.
//
// Note: --dek on the command line is visible to other processes on the
// same host (e.g. via `ps`) for the life of this process, like any
// command-line argument. That's a general limitation of passing secrets on
// argv, not specific to this tool.

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

// `hkdfguard_wrap_dek` no longer creates a KEK on first use -- that's now
// this tool's own responsibility, one call earlier (see `run` below),
// exactly the same as any other caller of the library.
@_silgen_name("hkdfguard_create_kek")
func hkdfguard_create_kek(_ service: UnsafePointer<CChar>?) -> Int32

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

struct Args {
    var keyFilePath: String
    var serviceName: String
    var dekBase64: String
    var force: Bool
}

enum ParseOutcome {
    case run(Args)
    case help
}

func printUsage() {
    FileHandle.standardError.write(
        "Usage: \(programName) <key-file-path> --service-name|-sn <name> --dek|-d <base64> [--force|-f]\n"
            .data(using: .utf8)!
    )
}

func parseArgs(_ arguments: [String]) throws -> ParseOutcome {
    var keyFilePath: String?
    var serviceName: String?
    var dekBase64: String?
    var force = false

    var iterator = arguments.dropFirst().makeIterator() // skip argv[0]
    while let arg = iterator.next() {
        switch arg {
        case "--help", "-h":
            return .help
        case "--force", "-f":
            force = true
        case "--service-name", "-sn":
            guard let value = iterator.next() else {
                throw CLIError("\(arg) requires a value")
            }
            guard !value.isEmpty else {
                throw CLIError("--service-name must not be empty")
            }
            serviceName = value
        case "--dek", "-d":
            guard let value = iterator.next() else {
                throw CLIError("\(arg) requires a value")
            }
            dekBase64 = value
        default:
            if keyFilePath == nil, !arg.hasPrefix("-") {
                keyFilePath = arg
            } else {
                throw CLIError("unrecognized argument: \(arg)")
            }
        }
    }

    guard let keyFilePath else { throw CLIError("missing required <key-file-path>") }
    guard let serviceName else { throw CLIError("missing required --service-name|-sn") }
    guard let dekBase64 else { throw CLIError("missing required --dek|-d") }

    return .run(
        Args(
            keyFilePath: keyFilePath,
            serviceName: serviceName,
            dekBase64: dekBase64,
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

// MARK: - Wrap

// Calls hkdfguard_wrap_dek, retrying once at the library-reported required
// size if the initial buffer was too small -- same pattern as the Linux
// tool's `wrap_dek`. Takes `dek` as `Data` rather than `[UInt8]` so the
// caller's already-tightly-scoped, zero-on-exit buffer (see `run` below) is
// the only copy of the plaintext DEK that ever exists -- converting to
// `[UInt8]` first would leave a second, unzeroed copy sitting in memory for
// the rest of the process's life.
func wrapDek(service: String, dek: Data) throws -> [UInt8] {
    var wrapped = [UInt8](repeating: 0, count: initialWrappedCapacity)
    var wrappedLen = Int32(wrapped.count)

    func callOnce() -> Int32 {
        service.withCString { servicePtr in
            wrapped.withUnsafeMutableBufferPointer { wrappedBuf in
                dek.withUnsafeBytes { dekBuf in
                    hkdfguard_wrap_dek(
                        servicePtr,
                        dekBuf.bindMemory(to: UInt8.self).baseAddress,
                        Int32(dek.count),
                        wrappedBuf.baseAddress,
                        &wrappedLen
                    )
                }
            }
        }
    }

    var rc = callOnce()
    if rc == HKDFGuardStatus.outputBufferTooSmall.rawValue {
        // wrappedLen now holds the size the library actually needs; retry once at that size.
        wrapped = [UInt8](repeating: 0, count: Int(wrappedLen))
        rc = callOnce()
    }

    guard rc == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_wrap_dek failed: \(describeStatus(rc))")
    }

    return Array(wrapped.prefix(Int(wrappedLen)))
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
// replace.
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
func secureOverwriteAndRemoveIfExists(path: String) throws {
    let fd = open(path, O_WRONLY)
    guard fd >= 0 else {
        let err = errno
        if err == ENOENT {
            return // nothing to overwrite or delete
        }
        if err == EACCES || err == EPERM {
            // Can't write to it -- skip the overwrite passes and go
            // straight to trying to remove it.
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

func run(_ args: Args) throws {
    // Fast, friendly pre-check: fail before ever touching the Secure
    // Enclave/Keychain if the output path obviously already exists,
    // rather than making the caller pay for a full wrap operation just to
    // find out at the very end. writeWrappedKeyFile's O_EXCL is the actual
    // correctness guarantee against the exists-then-create race; this is
    // purely a fail-fast convenience on top of it.
    if !args.force && FileManager.default.fileExists(atPath: args.keyFilePath) {
        throw CLIError("\(args.keyFilePath) already exists; pass --force|-f to overwrite")
    }

    // `args.serviceName` is not secret -- it's a logical identifier, not key
    // material -- so no special scoping is needed for it. Validated before
    // the DEK's own tightly-scoped block below.
    try validateServiceCharset(args.serviceName)

    // hkdfguard_wrap_dek no longer creates a KEK on first use (see its own
    // header comment) -- this tool always wants one to exist before it
    // wraps, so it explicitly ensures that here. Safe to call every run,
    // including when a KEK already exists for this service:
    // hkdfguard_create_kek is idempotent.
    let createStatus = args.serviceName.withCString { hkdfguard_create_kek($0) }
    guard createStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_create_kek failed: \(describeStatus(createStatus))")
    }

    var args = args
    let wrapped: [UInt8]
    do {
        guard var dekData = Data(base64Encoded: args.dekBase64) else {
            throw CLIError("--dek is not valid base64")
        }

        // The base64 *text* has now served its only purpose: drop this
        // process's one owned reference to it right here, rather than
        // leaving it sitting in `args` for the rest of this function.
        // Unlike the decoded DEK *bytes* below, Swift's String has no
        // supported API for in-place zeroing (no mutable-buffer access to a
        // String's storage) -- reassigning to an empty literal drops the
        // only strong reference to the original buffer so it becomes
        // eligible for deallocation at the earliest opportunity, which is
        // the best this language allows, not a guaranteed wipe the way
        // SecureZeroMemory/Zeroizing are on this project's Windows/Linux
        // tools. This does not erase the original command-line argument the
        // OS/process table still holds elsewhere -- see this file's header
        // comment on that inherent, unavoidable argv-visibility limitation.
        args.dekBase64 = ""

        // Scrub our local copy of the decoded DEK bytes the instant this
        // block ends, on every exit path -- immediately after wrapDek is
        // done with it, not at the end of run() (which would otherwise
        // leave it sitting in memory, unused but unwiped, through the
        // potentially-slow 8-pass secure-overwrite and the final file
        // write below).
        defer {
            _ = dekData.withUnsafeMutableBytes { raw in
                raw.initializeMemory(as: UInt8.self, repeating: 0)
            }
        }

        guard dekData.count == dekLen else {
            throw CLIError("--dek must decode to exactly \(dekLen) bytes, got \(dekData.count)")
        }

        wrapped = try wrapDek(service: args.serviceName, dek: dekData)
        // the `defer` above zeroes `dekData` here, as this scope ends --
        // immediately after wrapDek returns the wrapped (encrypted, no
        // longer secret) form, which is the only thing that survives past
        // this point.
    }

    try writeWrappedKeyFile(path: args.keyFilePath, bytes: wrapped, force: args.force)

    print("wrapped key written to \(args.keyFilePath) (\(wrapped.count) bytes, permissions 0640, service \"\(args.serviceName)\")")
}

// MARK: - Entry point

do {
    switch try parseArgs(CommandLine.arguments) {
    case .help:
        printUsage()
        exit(0)
    case .run(let args):
        do {
            try run(args)
            exit(0)
        } catch {
            FileHandle.standardError.write("error: \(error)\n".data(using: .utf8)!)
            exit(1)
        }
    }
} catch {
    // An argument-parsing failure: print the error and usage, then exit 2
    // -- distinct from a runtime failure (exit 1) inside `run`, matching
    // the Linux tool's own exit-code convention.
    FileHandle.standardError.write("error: \(error)\n".data(using: .utf8)!)
    printUsage()
    exit(2)
}
