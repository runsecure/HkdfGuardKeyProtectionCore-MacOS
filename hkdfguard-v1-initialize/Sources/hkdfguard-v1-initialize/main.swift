// CLI tool: ensures a persistent KEK exists for the given service, then
// wraps a Data Encryption Key (DEK) under it -- either one the library
// generates on the spot (--generate) or one the caller supplies -- and
// writes the wrapped payload to a file.
//
// Calls into the HkdfGuard library through its stable C ABI
// (`hkdfguard_kek_exists`, `hkdfguard_create_kek` if needed, then
// `hkdfguard_generate_and_wrap_dek` or `hkdfguard_wrap_dek`), the same interface
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
//   hkdfguard-v1-initialize <key-file-path> \
//       --service-name|-sn <name> \
//       ( --generate|-g | --dek-stdin | --dek-file <path> ) \
//       [--force|-f]
//
// Exactly one DEK source is required:
//   --generate|-g      the library generates a fresh random 32-byte DEK from
//                      the OS CSPRNG and wraps it in a single call. No
//                      plaintext DEK ever exists in this process, on the
//                      command line, or in any shell history -- the only
//                      way to obtain it afterward is hkdfguard_unwrap_dek
//                      under the same service. Recommended.
//   --dek-stdin        base64 DEK read from standard input (e.g. piped from
//                      another tool or a secret store; trailing newline ok).
//   --dek-file <path>  base64 DEK read from a file.
//
// There is deliberately no way to pass the DEK itself as a command-line
// argument: an argv value is visible to every other process on the host
// (`ps`) for the life of the process and is recorded in the invoking
// shell's history file. Both stdin and a file avoid that entirely, and
// --generate never exposes a plaintext DEK anywhere.
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
// Nothing persistent -- no Secure Enclave key, no keychain item, no file --
// is created until every argument has been validated, so a malformed
// invocation never leaves a freshly provisioned KEK behind.

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
// this tool's own responsibility, before wrapping (see `ensureKEK` below),
// exactly the same as any other caller of the library: ask whether one
// exists, and create it only if the answer is a definite "no".
@_silgen_name("hkdfguard_kek_exists")
func hkdfguard_kek_exists(_ service: UnsafePointer<CChar>?, _ outExists: UnsafeMutablePointer<Int32>?) -> Int32

@_silgen_name("hkdfguard_create_kek")
func hkdfguard_create_kek(_ service: UnsafePointer<CChar>?) -> Int32

// Generates a fresh 32-byte DEK inside the library and wraps it in one call
// -- the --generate path, where this process never holds a plaintext DEK.
@_silgen_name("hkdfguard_generate_and_wrap_dek")
func hkdfguard_generate_and_wrap_dek(
    _ service: UnsafePointer<CChar>?,
    _ out: UnsafeMutablePointer<UInt8>?,
    _ outLen: UnsafeMutablePointer<Int32>?
) -> Int32

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
    case generate            // --generate|-g
    case stdin               // --dek-stdin
    case file(String)        // --dek-file <path>

    var flag: String {
        switch self {
        case .generate: return "--generate"
        case .stdin: return "--dek-stdin"
        case .file: return "--dek-file"
        }
    }
}

struct Args {
    var keyFilePath: String
    var serviceName: String
    var dekSource: DekSource
    var force: Bool
}

enum ParseOutcome {
    case run(Args)
    case help
}

let dekSourceFlags = "--generate|-g | --dek-stdin | --dek-file <path>"

func printUsage() {
    FileHandle.standardError.write(
        """
        Usage: \(programName) <key-file-path> --service-name|-sn <name> \\
                   ( \(dekSourceFlags) ) [--force|-f]

          --generate|-g       generate a fresh random 32-byte DEK inside the library and
                              wrap it; no plaintext DEK ever exists in this process, on
                              the command line, or in shell history (recommended)
          --dek-stdin         read the base64 DEK from standard input
          --dek-file <path>   read the base64 DEK from a file
          --force|-f          securely overwrite an existing <key-file-path>

        The DEK is never accepted as a command-line argument (it would be visible
        to other processes via ps and recorded in shell history).

        """.data(using: .utf8)!
    )
}

func parseArgs(_ arguments: [String]) throws -> ParseOutcome {
    var keyFilePath: String?
    var serviceName: String?
    var dekSources: [DekSource] = []
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
        case "--generate", "-g":
            dekSources.append(.generate)
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
            if keyFilePath == nil, !arg.hasPrefix("-") {
                keyFilePath = arg
            } else {
                throw CLIError("unrecognized argument: \(arg)")
            }
        }
    }

    guard let keyFilePath else { throw CLIError("missing required <key-file-path>") }
    guard let serviceName else { throw CLIError("missing required --service-name|-sn") }
    guard !dekSources.isEmpty else {
        throw CLIError("missing required DEK source: one of \(dekSourceFlags)")
    }
    guard dekSources.count == 1 else {
        throw CLIError("conflicting DEK sources (\(dekSources.map(\.flag).joined(separator: ", "))): give exactly one of \(dekSourceFlags)")
    }

    return .run(
        Args(
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

// MARK: - KEK provisioning

// Makes sure a KEK exists for `service` before anything is wrapped under
// it: hkdfguard_kek_exists first, hkdfguard_create_kek only on a definite
// "no key yet". Anything other than a clean yes/no from the exists check --
// keychainAccessDenied, keychainReadFailed, kekCorrupted, enclaveUnavailable
// -- stops here with that specific reason, rather than falling through to
// a create attempt whose failure would be reported against the wrong step.
func ensureKEK(service: String) throws {
    var exists: Int32 = 0
    let existsStatus = service.withCString { hkdfguard_kek_exists($0, &exists) }
    guard existsStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_kek_exists failed: \(describeStatus(existsStatus))")
    }
    if exists != 0 {
        return
    }

    let createStatus = service.withCString { hkdfguard_create_kek($0) }
    guard createStatus == HKDFGuardStatus.success.rawValue else {
        throw CLIError("hkdfguard_create_kek failed: \(describeStatus(createStatus))")
    }
}

// MARK: - Wrap

// Calls `attempt` with an output buffer of initialWrappedCapacity and, if
// the library answers outputBufferTooSmall (having written the size it
// actually needs into the length out-parameter), retries exactly once at
// that size -- same pattern as the Linux tool's `wrap_dek`. Shared by both
// wrap entry points below so there is one retry implementation.
func callWithWrappedBuffer(
    _ functionName: String,
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
    try callWithWrappedBuffer("hkdfguard_wrap_dek") { outPtr, outLen in
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

// The --generate path: the library sources the DEK from the OS CSPRNG,
// wraps it, and zeroes its own copy before returning -- this process only
// ever sees the wrapped form.
func generateAndWrapDek(service: String) throws -> [UInt8] {
    try callWithWrappedBuffer("hkdfguard_generate_and_wrap_dek") { outPtr, outLen in
        service.withCString { servicePtr in
            hkdfguard_generate_and_wrap_dek(servicePtr, outPtr, outLen)
        }
    }
}

// MARK: - Reading a caller-supplied DEK

// Returns the base64 text for a caller-supplied DEK source. Never called
// for .generate, which has no text to read.
func readSuppliedDekBase64(_ source: DekSource) throws -> String {
    switch source {
    case .generate:
        preconditionFailure("--generate has no DEK text to read")

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
    // Same fail-fast idea for --force: a symlink or non-regular file at the
    // path will be refused by the overwrite step anyway; refusing it here
    // first means no Secure Enclave/keychain work is spent on a command
    // that cannot complete.
    if args.force {
        try refuseUnlessAbsentOrRegularFile(path: args.keyFilePath)
    }

    // `args.serviceName` is not secret -- it's a logical identifier, not key
    // material -- so no special scoping is needed for it. Validated before
    // any DEK is read or generated.
    try validateServiceCharset(args.serviceName)

    let wrapped: [UInt8]
    switch args.dekSource {
    case .generate:
        // Nothing persistent is touched until every argument has been
        // validated -- which, with no DEK to validate, is now.
        // hkdfguard_wrap_dek/hkdfguard_generate_and_wrap_dek no longer
        // create a KEK on first use, so this tool checks for one and creates
        // it only if missing. This process never holds the plaintext DEK.
        try ensureKEK(service: args.serviceName)
        wrapped = try generateAndWrapDek(service: args.serviceName)

    case .stdin, .file:
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
                throw CLIError("\(args.dekSource.flag): the DEK must decode to exactly \(dekLen) bytes, got \(dekData.count)")
            }

            // Only now -- every argument validated -- is anything persistent
            // touched. Deliberately after the DEK checks above: a malformed
            // DEK must never leave a freshly provisioned Secure Enclave key
            // and keychain item behind for a command that then fails. The
            // decoded DEK lives a few milliseconds longer for it, still
            // zeroed by the defer above the instant this block ends.
            try ensureKEK(service: args.serviceName)

            wrapped = try wrapDek(service: args.serviceName, dek: dekData)
            // the `defer` above zeroes `dekData` here, as this scope ends --
            // immediately after wrapDek returns the wrapped (encrypted, no
            // longer secret) form, which is the only thing that survives
            // past this point.
        }
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
