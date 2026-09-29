//
//  HkdfGuardCommandLineToolTests.swift
//  HkdfGuardKeyProtectionEnclaveTests
//

import Testing
import Foundation
import CryptoKit
@testable import HkdfGuardKeyProtectionEnclave

/// Exercises the actual `hkdfguard-v1-initialize` command-line tool
/// (`../hkdfguard-v1-initialize`) as a real, separate process — not the
/// `hkdfguard_wrap_dek` C ABI function it calls internally, which every
/// other test in this suite already covers directly. This is the one
/// place that answers "does the tool a real caller runs actually work,
/// end to end": argument parsing, file I/O (permissions, `--force`
/// overwrite/secure-delete), exit codes, and — the scenario this file
/// exists for — that a DEK wrapped by that separate process can be
/// recovered by *application code* (the library, called directly here the
/// same way a consuming app would) via `hkdfguard_unwrap_dek`.
///
/// That last point is confirmed to work correctly (byte-for-byte, proven
/// below) but is NOT free of ceremony: the CLI tool and this test host are
/// two differently-signed binaries, and the Secure Enclave key the CLI
/// creates is persisted as an ordinary keychain item with no shared
/// `kSecAttrAccessGroup` (see the comment in
/// HkdfGuardKeyProtectionEnclave.entitlements on why not). Its default ACL
/// therefore trusts exactly the creating binary's code signature, or
/// falls back to an interactive macOS keychain-access prompt for anyone
/// else — confirmed directly in the system log (`log show`) while
/// developing this suite:
///
///   securityd: displaying keychain prompt for .../xctest(59175);
///   ACL: ThresholdAclSubject(1 of 2)
///     [CodeSignatureAclSubject[path: .../hkdfguard-v1-initialize]]
///     [KeychainPromptAclSubject(desc: com.hkdfguard.tests.cli.roundtrip.1)]
///
/// The first time this test host (as a new, not-yet-approved requesting
/// identity) reads a keychain item the CLI created, that prompt appears
/// and blocks until a human clicks it — observed taking over half an hour
/// in an unattended run. Once approved, that identity seems to be trusted
/// going forward: three more CLI→app round trips in the same run
/// afterward completed in single-digit seconds each, not the same long
/// wait. See `interactiveKeychainAccessEnabled` below for how the affected
/// tests are gated because of this.
///
/// This is not just a test-environment quirk: it's the same prompt a real
/// differently-signed consuming application would hit in production
/// unwrapping a DEK the CLI provisioned, absent a shared keychain-access-
/// group entitlement between them.
///
/// Separately: the *first* CLI subprocess launch after a freshly built
/// binary was also observed to take several seconds longer than later
/// launches — Gatekeeper's first-launch check, most likely — independent
/// of the keychain-prompt issue above. `ensureCLIBuilt()`
/// below deliberately builds the tool once, up front, outside of any
/// individual test's timing, so that one-time cost doesn't land on
/// whichever test happens to run first.
///
/// `.serialized` for the same Secure Enclave/SEP concurrency reason as
/// `HkdfGuardKeyProtectionEnclaveWrapUnwrapTests`. Every test that actually
/// exercises the CLI's wrap path is additionally gated on
/// `SecureEnclave.isAvailable` — see `secureEnclaveAvailableComment` below
/// — so this suite degrades gracefully to just its pure argument-handling
/// tests (`cliRejects*`, `cliPrintsUsageOnHelp`) on a CI/VM runner with no
/// real Secure Enclave, rather than failing outright.
@Suite(.serialized)
struct HkdfGuardCommandLineToolTests {

    // MARK: - Opt-in gate for tests that cross the CLI -> application-code
    // keychain boundary

    /// Set `HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1` in the test host's
    /// environment (e.g. an Xcode scheme's Test action, or
    /// `env HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 xcodebuild test ...`)
    /// to opt into the four tests below gated on this. They're excluded
    /// from the default run — rather than left enabled and just slow —
    /// because the *first* time they run against a keychain/machine that
    /// hasn't already approved this test host's identity, macOS shows a
    /// real interactive keychain-access prompt (see the suite's doc
    /// comment above) that nothing here can dismiss automatically. Be
    /// present to click "Allow" once when running these; after that
    /// approval, reruns are fast.
    private static let interactiveKeychainAccessEnabled =
        ProcessInfo.processInfo.environment["HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS"] != nil

    private static let interactiveKeychainAccessComment: Comment =
        "requires a one-time interactive keychain approval; set HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 to opt in — see this suite's doc comment"

    /// The cross-process round trips below read, in *this* process, a KEK
    /// the bare SwiftPM-built CLI created. That CLI is a plain Mach-O with
    /// no entitlements, so it always runs in legacy keychain mode; the read
    /// can only succeed if this host runs in legacy mode too (the two
    /// keychains are disjoint). Hosted in the entitled HkdfGuardTestHost app
    /// these are skipped, and the data-protection equivalent -- provisioned
    /// by the *bundled* CLI, no prompt involved -- runs instead (see the end
    /// of this file).
    private static let legacyCrossProcessRoundTripEnabled =
        interactiveKeychainAccessEnabled && hkdfguardKeychainMode == .legacy

    /// Every test below that actually runs the CLI's wrap path needs a
    /// real Secure Enclave — on a CI/VM runner (`SecureEnclave.isAvailable
    /// == false`), the CLI itself would fail with `keyUnavailable` before
    /// any of what these tests are checking even comes into play. Folded
    /// into `interactiveKeychainAccessEnabled` below for the four tests
    /// that need both gates; used alone for the one default-running test
    /// that wraps but doesn't cross the interactive-keychain boundary.
    private static let secureEnclaveAvailableComment: Comment =
        "requires a real Secure Enclave — not available on CI/VM runners; run on real Mac hardware before committing/requesting a build"

    private static let interactiveKeychainAndSecureEnclaveComment: Comment =
        "requires a real Secure Enclave and a one-time interactive keychain approval; set HKDFGUARD_RUN_INTERACTIVE_KEYCHAIN_TESTS=1 on real Mac hardware to opt in — see this suite's doc comment"

    // MARK: - Locating and building the tool this suite exercises

    private static let dekLength = 32

    // This file lives at <repo>/HkdfGuardKeyProtectionEnclaveTests/…, so
    // its own path is a stable way to find the repo root regardless of
    // where/how the test bundle itself is run from — the same technique
    // hkdfguard-v1-initialize/Package.swift uses to locate the dylib it
    // links against.
    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // HkdfGuardKeyProtectionEnclaveTests/
        .deletingLastPathComponent() // repo root

    private static let dylibPath = repoRoot
        .appendingPathComponent("build/Release/HkdfGuard.Kms.MacOS.v1.dylib")
        .path

    private static let cliPackageDir = repoRoot
        .appendingPathComponent("hkdfguard-v1-initialize")

    private static let cliExecutablePath = repoRoot
        .appendingPathComponent("hkdfguard-v1-initialize/.build/release/hkdfguard-v1-initialize")
        .path

    private struct ToolBuildError: Error, CustomStringConvertible {
        let description: String
    }

    /// Starts reading `handle` to EOF on a background queue immediately and
    /// returns a closure that blocks until that read completes and hands
    /// back the bytes. Used by `run` below so both of a child's output
    /// pipes are drained *while* it runs — see the comment there.
    private static func drainInBackground(_ handle: FileHandle) -> () -> Data {
        let done = DispatchGroup()
        var data = Data()
        done.enter()
        DispatchQueue.global(qos: .utility).async {
            data = handle.readDataToEndOfFile()
            done.leave()
        }
        return {
            done.wait()
            return data
        }
    }

    /// Runs `arguments` to completion and returns its exit code plus
    /// captured stdout/stderr.
    ///
    /// Both pipes are drained concurrently, from the moment the child
    /// starts, and `waitUntilExit` is only called after that draining is
    /// under way. Reading a pipe only *after* the child exits deadlocks as
    /// soon as the child writes more than the pipe's buffer (64KB on
    /// macOS): the child blocks in `write(2)` waiting for a reader, the
    /// parent blocks in `waitUntilExit` waiting for the child. The CLI
    /// itself writes a line or two, but this same helper also launches
    /// `xcodebuild` and `swift build` (via `ensureDylibBuilt`/
    /// `ensureCLIBuilt`), whose logs are far larger than 64KB — observed
    /// directly: on a clean checkout the nested Release-dylib build
    /// finished its work in under a minute and then sat for 20 minutes
    /// blocked in `write` on a full 65536-byte pipe, with this test host
    /// parked in `waitUntilExit`. That is what a "hanging" CLI test looked
    /// like from the outside.
    ///
    /// `stdin`, when given, is written to the child's standard input and
    /// then closed; otherwise the child's stdin is /dev/null, so no child
    /// can ever block waiting on this test host's inherited stdin.
    @discardableResult
    private static func run(_ executableURL: URL, _ arguments: [String], currentDirectory: URL? = nil, stdin: Data? = nil) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        if let currentDirectory {
            process.currentDirectoryURL = currentDirectory
        }

        // Process() inherits the parent's environment by default — here,
        // the xctest host's. Xcode points that host's DYLD_LIBRARY_PATH/
        // DYLD_FRAMEWORK_PATH at its own DerivedData Products directory so
        // the test bundle can find HkdfGuardKeyProtectionEnclave.framework;
        // dyld's DYLD_LIBRARY_PATH override resolves @rpath/<leaf-name>
        // against *any* matching filename found there first, ahead of a
        // launched executable's own embedded rpath. Confirmed directly: a
        // stale, same-named dylib left behind in that DerivedData directory
        // from an earlier build caused the CLI subprocess launched below to
        // silently load that wrong, outdated dylib instead of the current
        // one at build/Release — producing a pre-fingerprint 124-byte
        // wrapped payload instead of 156, and in other runs, behavior odd
        // enough to hang. Stripping DYLD_* here removes that whole class of
        // environment leakage regardless of what DerivedData happens to
        // contain.
        var environment = ProcessInfo.processInfo.environment
        for key in environment.keys where key.hasPrefix("DYLD_") {
            environment.removeValue(forKey: key)
        }
        process.environment = environment
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let stdinPipe: Pipe?
        if stdin != nil {
            stdinPipe = Pipe()
            process.standardInput = stdinPipe
        } else {
            stdinPipe = nil
            process.standardInput = FileHandle.nullDevice
        }

        try process.run()
        let stdoutBytes = drainInBackground(stdoutPipe.fileHandleForReading)
        let stderrBytes = drainInBackground(stderrPipe.fileHandleForReading)
        if let stdinPipe, let stdin {
            // Small payloads only (a base64 DEK), well under the pipe buffer,
            // so this write can't block; close signals EOF to the child.
            stdinPipe.fileHandleForWriting.write(stdin)
            try? stdinPipe.fileHandleForWriting.close()
        }
        process.waitUntilExit()

        let stdout = String(data: stdoutBytes(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrBytes(), encoding: .utf8) ?? ""
        return (process.terminationStatus, stdout, stderr)
    }

    /// Builds the Release dylib the CLI tool links against, if it isn't
    /// already sitting at the fixed path both this file and the tool's own
    /// Package.swift expect. A CI/dev environment that already ran a
    /// Release build of `HkdfGuardKeyProtectionEnclaveDylib` pays nothing
    /// here beyond the file-existence check.
    private static func ensureDylibBuilt() throws {
        guard !FileManager.default.fileExists(atPath: dylibPath) else { return }

        let result = try run(
            URL(fileURLWithPath: "/usr/bin/xcodebuild"),
            [
                "-project", repoRoot.appendingPathComponent("HkdfGuardKeyProtectionEnclave.xcodeproj").path,
                "-target", "HkdfGuardKeyProtectionEnclaveDylib",
                "-configuration", "Release",
                "build"
            ],
            currentDirectory: repoRoot
        )
        guard result.exitCode == 0, FileManager.default.fileExists(atPath: dylibPath) else {
            throw ToolBuildError(description: "failed to build HkdfGuardKeyProtectionEnclaveDylib (exit \(result.exitCode)):\n\(result.stdout)\n\(result.stderr)")
        }
    }

    /// Builds the `hkdfguard-v1-initialize` executable via SwiftPM, if it
    /// isn't already built. Depends on `ensureDylibBuilt()` having run
    /// first — the tool links against the dylib's fixed path at build time
    /// (see its own Package.swift) as well as at run time via `-rpath`.
    private static func ensureCLIBuilt() throws {
        try ensureDylibBuilt()
        guard !FileManager.default.fileExists(atPath: cliExecutablePath) else { return }

        let result = try run(
            URL(fileURLWithPath: "/usr/bin/env"),
            ["swift", "build", "-c", "release"],
            currentDirectory: cliPackageDir
        )
        guard result.exitCode == 0, FileManager.default.fileExists(atPath: cliExecutablePath) else {
            throw ToolBuildError(description: "failed to build hkdfguard-v1-initialize (exit \(result.exitCode)):\n\(result.stdout)\n\(result.stderr)")
        }
    }

    /// Runs the built `hkdfguard-v1-initialize` executable with
    /// `arguments`, building it first if needed.
    private static func runCLI(_ arguments: [String], stdin: Data? = nil) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        try ensureCLIBuilt()
        return try run(URL(fileURLWithPath: cliExecutablePath), arguments, stdin: stdin)
    }

    /// Runs the CLI's `provision` command for `service` and asserts it
    /// succeeded. Since `wrap` never creates a KEK, every test that expects
    /// a wrap to succeed calls this first -- exactly as a real operator must.
    private static func provision(service: String, sourceLocation: SourceLocation = #_sourceLocation) throws {
        let result = try runCLI(["provision", "--service-name", service])
        #expect(result.exitCode == 0, "provision failed: \(result.stderr)", sourceLocation: sourceLocation)
    }

    // MARK: - Helpers shared with the round-trip/tamper tests

    private static func randomDEK() -> [UInt8] {
        (0..<dekLength).map { _ in UInt8.random(in: .min ... .max) }
    }

    /// `dek` as the CLI's `--dek-stdin` input: base64 plus the trailing
    /// newline `echo`/a piped tool would send. The CLI deliberately has no
    /// way to take a DEK as an argument, so this is how every test that
    /// supplies its own DEK feeds it in.
    private static func base64Stdin(_ dek: [UInt8]) -> Data {
        Data((Data(dek).base64EncodedString() + "\n").utf8)
    }

    /// Deletes the keychain item for `service`, via the `security` CLI
    /// rather than a direct `SecItemDelete` call. This isn't stylistic:
    /// every KEK this suite needs to clean up was created by the separate,
    /// differently-signed `hkdfguard-v1-initialize` process, and a plain
    /// `SecItemDelete` from *this* process (the test host) against such an
    /// item fails outright — confirmed directly while developing this
    /// suite, returning errSecInvalidOwnerEdit (-25244, "Invalid attempt
    /// to change the owner of this item"), silently, no interactive prompt
    /// at all (unlike the *read* path — see the suite's doc comment).
    /// `/usr/bin/security`, an Apple-signed platform binary, has broader
    /// keychain trust than an arbitrary third-party process and reliably
    /// succeeds where `SecItemDelete` here does not.
    private static func deleteKEK(service: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        // Lowercased to match what the library actually stored (it
        // normalizes `service` before any keychain use).
        process.arguments = ["delete-generic-password", "-s", service.lowercased(), "-a", hkdfguardKeychainAccount]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }

    /// Whether a keychain item exists for `service`. Via the `security` CLI
    /// for the same cross-process reason as `deleteKEK` above; this is an
    /// attribute lookup only (no `-w`/`-g`, so the item's data is never
    /// read and no ACL prompt can be triggered).
    private static func kekItemExists(service: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["find-generic-password", "-s", service.lowercased(), "-a", hkdfguardKeychainAccount]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    /// The "application code" side of every test below: calls
    /// `hkdfguard_unwrap_dek` directly, exactly the way any Swift/C/other
    /// consumer of this library would, on whatever bytes the CLI tool
    /// wrote to disk.
    private static func unwrapInApplicationCode(
        _ wrapped: [UInt8],
        service: String
    ) -> (status: Int32, dek: [UInt8]) {
        var out = [UInt8](repeating: 0, count: 1024)
        var outLen = Int32(out.count)
        let status = service.withCString { serviceCStr in
            wrapped.withUnsafeBufferPointer { wrappedBuf in
                out.withUnsafeMutableBufferPointer { outBuf in
                    hkdfguard_unwrap_dek(
                        servicePtr: serviceCStr,
                        wrappedPtr: wrappedBuf.baseAddress!,
                        wrappedLen: Int32(wrapped.count),
                        outPtr: outBuf.baseAddress!,
                        outLen: &outLen
                    )
                }
            }
        }
        return (status, Array(out.prefix(Int(max(outLen, 0)))))
    }

    /// A temp file path under the system temp directory, not yet created.
    private static func makeTempFilePath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("hkdfguard-cli-test-\(UUID().uuidString).bin")
            .path
    }

    // MARK: - Round trip: CLI wraps, application code decrypts

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliWrappedDekIsRecoveredByApplicationCode() throws {
        let service = "com.hkdfguard.tests.cli.roundtrip"
        defer { Self.deleteKEK(service: service) }

        let dek = Self.randomDEK()
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let result = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(dek)
        )
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        #expect(FileManager.default.fileExists(atPath: keyFilePath))

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == dek)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrappedFileHasExpectedLengthAndPermissions() throws {
        let service = "com.hkdfguard.tests.cli.file.attributes"
        defer { Self.deleteKEK(service: service) }

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let result = try Self.runCLI(
            ["wrap", "-kf", keyFilePath, "-sn", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")

        let attributes = try FileManager.default.attributesOfItem(atPath: keyFilePath)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue
        #expect(permissions == 0o640)

        let wrapped = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))
        #expect(wrapped.count == 156) // 32-byte KEK fingerprint + 64-byte ephemeral pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag
    }

    // MARK: - File handling: refuses to clobber, --force overwrites correctly

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliRefusesToOverwriteWithoutForce() throws {
        let service = "com.hkdfguard.tests.cli.no.overwrite"
        defer { Self.deleteKEK(service: service) }

        let firstDek = Self.randomDEK()
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let firstResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(firstDek)
        )
        #expect(firstResult.exitCode == 0, "CLI failed: \(firstResult.stderr)")

        let secondResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(secondResult.exitCode != 0)

        // The original file, and the DEK it wraps, must be untouched.
        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == firstDek)
    }

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliForceOverwritesWithNewDek() throws {
        let service = "com.hkdfguard.tests.cli.force.overwrite"
        defer { Self.deleteKEK(service: service) }

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let firstResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(firstResult.exitCode == 0, "CLI failed: \(firstResult.stderr)")

        let secondDek = Self.randomDEK()
        let secondResult = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(secondDek)
        )
        #expect(secondResult.exitCode == 0, "CLI --force failed: \(secondResult.stderr)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == secondDek)
    }

    // MARK: - Input validation, via the real CLI's own argument handling

    @Test func cliRejectsNonBase64Dek() throws {
        let service = "com.hkdfguard.tests.cli.bad.dek"
        defer { Self.deleteKEK(service: service) } // only needed if the assertion below fails
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Data("not-valid-base64!!\n".utf8)
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("not valid base64"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        // A rejected invocation must have no persistent side effects: the
        // CLI used to provision the KEK before validating --dek, leaving a
        // Secure Enclave key and keychain item behind for every typo.
        #expect(!Self.kekItemExists(service: service), "a rejected --dek must not provision a KEK")
    }

    @Test func cliRejectsWrongLengthDek() throws {
        let service = "com.hkdfguard.tests.cli.short.dek"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin([UInt8](repeating: 0, count: 16))
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("exactly 32 bytes"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(!Self.kekItemExists(service: service), "a rejected --dek must not provision a KEK")
    }

    // MARK: - --force never follows symlinks or touches non-regular files

    @Test func cliForceRefusesToOverwriteThroughSymlink() throws {
        // A link planted at <key-file-path> must not redirect the
        // destructive overwrite passes onto whatever it points at. Refused
        // before any Secure Enclave/keychain work, so no KEK appears either.
        let service = "com.hkdfguard.tests.cli.force.symlink"
        defer { Self.deleteKEK(service: service) }
        let targetPath = Self.makeTempFilePath()
        let linkPath = Self.makeTempFilePath()
        defer {
            try? FileManager.default.removeItem(atPath: linkPath)
            try? FileManager.default.removeItem(atPath: targetPath)
        }
        let original = Data("do not destroy me".utf8)
        try original.write(to: URL(fileURLWithPath: targetPath))
        try FileManager.default.createSymbolicLink(atPath: linkPath, withDestinationPath: targetPath)

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", linkPath, "--service-name", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("symbolic link"), "stderr: \(result.stderr)")

        let targetAfter = try Data(contentsOf: URL(fileURLWithPath: targetPath))
        #expect(targetAfter == original)
        #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: linkPath)) == targetPath)
        #expect(!Self.kekItemExists(service: service))
    }

    @Test func cliForceRefusesNonRegularFile() throws {
        let service = "com.hkdfguard.tests.cli.force.fifo"
        defer { Self.deleteKEK(service: service) }
        let fifoPath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: fifoPath) }
        #expect(mkfifo(fifoPath, 0o600) == 0)

        let result = try Self.runCLI(
            ["wrap", "--key-file-path", fifoPath, "--service-name", service, "--dek-stdin", "--force"],
            stdin: Self.base64Stdin(Self.randomDEK())
        )
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("not a regular file"), "stderr: \(result.stderr)")

        var st = stat()
        #expect(lstat(fifoPath, &st) == 0)
        #expect((st.st_mode & S_IFMT) == S_IFIFO, "the FIFO must still be there, untouched")
        #expect(!Self.kekItemExists(service: service))
    }

    @Test func cliRejectsMissingRequiredArguments() throws {
        let result = try Self.runCLI(["wrap", "--service-name", "com.hkdfguard.tests.cli.missing.args"])
        #expect(result.exitCode == 2) // argument-parsing failure, distinct from a runtime failure
        #expect(result.stderr.contains("--key-file-path"))
    }

    @Test func cliPrintsUsageOnHelp() throws {
        let result = try Self.runCLI(["--help"])
        #expect(result.exitCode == 0)
        #expect(result.stderr.localizedCaseInsensitiveContains("usage"))
        #expect(result.stderr.contains("provision"))
        #expect(result.stderr.contains("wrap"))
        #expect(result.stderr.contains("--key-file-path"))
        #expect(result.stderr.contains("--dek-stdin"))
        #expect(result.stderr.contains("--dek-file"))
        #expect(!result.stderr.contains("--dek|"), "usage must not advertise a --dek argument")
        #expect(!result.stderr.contains("--generate"), "usage must not advertise DEK generation")
    }

    // MARK: - DEK sources: --dek-stdin, --dek-file (and the rejected --dek / --generate)

    @Test func cliRejectsGenerate() throws {
        // This tool wraps the pipeline's existing DEK -- the key its data was
        // already encrypted with -- so there is nothing for it to generate.
        let service = "com.hkdfguard.tests.cli.generate.rejected"
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        for flag in ["--generate", "-g"] {
            let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, flag])
            #expect(result.exitCode == 2, "\(flag): exit \(result.exitCode), stderr: \(result.stderr)")
            #expect(result.stderr.contains("not supported"))
            #expect(result.stderr.contains("--dek-stdin"))
            #expect(!FileManager.default.fileExists(atPath: keyFilePath))
            #expect(!Self.kekItemExists(service: service))
        }
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliDekStdinWrapsTheSuppliedDek() throws {
        let service = "com.hkdfguard.tests.cli.dek.stdin"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        // Trailing newline on purpose: that's what `echo`/a piped tool sends.
        try Self.provision(service: service)
        let stdin = Data((Data(Self.randomDEK()).base64EncodedString() + "\n").utf8)
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"], stdin: stdin)
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        #expect(!result.stderr.contains("warning:"))
        let wrapped = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))
        #expect(wrapped.count == 156)
    }

    @Test(.enabled(if: legacyCrossProcessRoundTripEnabled && SecureEnclave.isAvailable, interactiveKeychainAndSecureEnclaveComment))
    func cliDekStdinDekIsRecoveredByApplicationCode() throws {
        let service = "com.hkdfguard.tests.cli.dek.stdin.roundtrip"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        try Self.provision(service: service)
        let dek = Self.randomDEK()
        let stdin = Data((Data(dek).base64EncodedString() + "\n").utf8)
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"], stdin: stdin)
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0)
        #expect(recovered.dek == dek)
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliDekFileWrapsTheSuppliedDek() throws {
        let service = "com.hkdfguard.tests.cli.dek.file"
        defer { Self.deleteKEK(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        let dekFilePath = Self.makeTempFilePath()
        defer {
            try? FileManager.default.removeItem(atPath: keyFilePath)
            try? FileManager.default.removeItem(atPath: dekFilePath)
        }
        try (Data(Self.randomDEK()).base64EncodedString() + "\n").write(toFile: dekFilePath, atomically: true, encoding: .utf8)

        try Self.provision(service: service)
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-file", dekFilePath])
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        let wrapped = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))
        #expect(wrapped.count == 156)
    }

    @Test func cliRejectsDekAsCommandLineArgument() throws {
        // There is deliberately no --dek|-d: a DEK on argv is visible via ps
        // and lands in shell history. It must be refused at argument-parsing
        // time (exit 2) with an explanation pointing at the supported
        // sources, before any Secure Enclave or keychain work.
        let service = "com.hkdfguard.tests.cli.dek.argument.rejected"
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        for flag in ["--dek", "-d"] {
            let result = try Self.runCLI([
                "wrap",
                "--key-file-path", keyFilePath,
                "--service-name", service,
                flag, Data(Self.randomDEK()).base64EncodedString()
            ])
            #expect(result.exitCode == 2, "\(flag): exit \(result.exitCode), stderr: \(result.stderr)")
            #expect(result.stderr.contains("not supported"))
            #expect(result.stderr.contains("--dek-stdin"))
            #expect(!FileManager.default.fileExists(atPath: keyFilePath))
            #expect(!Self.kekItemExists(service: service))
        }
    }

    @Test func cliRejectsEmptyStdin() throws {
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", "com.hkdfguard.tests.cli.empty.stdin", "--dek-stdin"], stdin: Data())
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("no data on standard input"))
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
        #expect(!Self.kekItemExists(service: "com.hkdfguard.tests.cli.empty.stdin"))
    }

    @Test func cliRejectsConflictingDekSources() throws {
        let keyFilePath = Self.makeTempFilePath()
        let result = try Self.runCLI([
            "wrap",
            "--key-file-path", keyFilePath,
            "--service-name", "com.hkdfguard.tests.cli.conflicting.sources",
            "--dek-stdin",
            "--dek-file", "/dev/null"
        ])
        #expect(result.exitCode == 2) // argument-parsing failure
        #expect(result.stderr.contains("conflicting DEK sources"))
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test func cliRejectsMissingDekSource() throws {
        let keyFilePath = Self.makeTempFilePath()
        let result = try Self.runCLI(["wrap", "--key-file-path", keyFilePath, "--service-name", "com.hkdfguard.tests.cli.missing.source"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("missing required DEK source"))
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    // MARK: - provision / wrap split

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliProvisionCreatesKekAndIsIdempotent() throws {
        let service = "com.hkdfguard.tests.cli.provision.idempotent"
        defer { Self.deleteKEK(service: service) }
        #expect(!Self.kekItemExists(service: service))

        let first = try Self.runCLI(["provision", "--service-name", service])
        #expect(first.exitCode == 0, "provision failed: \(first.stderr)")
        #expect(first.stdout.contains("provisioned KEK"))
        #expect(Self.kekItemExists(service: service))

        let second = try Self.runCLI(["provision", "-sn", service])
        #expect(second.exitCode == 0, "second provision failed: \(second.stderr)")
        #expect(second.stdout.contains("already exists"))
        #expect(Self.kekItemExists(service: service))
    }

    @Test(.enabled(if: SecureEnclave.isAvailable, secureEnclaveAvailableComment))
    func cliWrapRefusesWithoutProvision() throws {
        // The point of the split: `wrap` must never create a KEK. Against a
        // never-provisioned service it fails, names the fix, and leaves
        // neither a keychain item nor an output file behind -- for every
        // DEK source.
        let service = "com.hkdfguard.tests.cli.wrap.unprovisioned"
        defer { Self.deleteKEK(service: service) }
        let dekFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: dekFilePath) }
        try (Data(Self.randomDEK()).base64EncodedString() + "\n").write(toFile: dekFilePath, atomically: true, encoding: .utf8)

        let attempts: [(args: [String], stdin: Data?)] = [
            (["--dek-stdin"], Self.base64Stdin(Self.randomDEK())),
            (["--dek-file", dekFilePath], nil),
        ]
        for attempt in attempts {
            let keyFilePath = Self.makeTempFilePath()
            defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

            let result = try Self.runCLI(
                ["wrap", "--key-file-path", keyFilePath, "--service-name", service] + attempt.args,
                stdin: attempt.stdin
            )
            #expect(result.exitCode == 1, "\(attempt.args): exit \(result.exitCode), stderr: \(result.stderr)")
            #expect(result.stderr.contains("no KEK exists"), "stderr: \(result.stderr)")
            #expect(result.stderr.contains("provision --service-name \(service)"), "stderr: \(result.stderr)")
            #expect(!FileManager.default.fileExists(atPath: keyFilePath))
            #expect(!Self.kekItemExists(service: service), "\(attempt.args): wrap must not have provisioned a KEK")
        }
    }

    @Test func cliProvisionRejectsInvalidServiceName() throws {
        let service = "com.hkdfguard.tests-provision-invalid"
        let result = try Self.runCLI(["provision", "--service-name", service])
        #expect(result.exitCode == 1)
        #expect(result.stderr.contains("alphanumeric"))
        #expect(!Self.kekItemExists(service: service))
    }

    @Test func cliRejectsMissingCommand() throws {
        let result = try Self.runCLI([])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("missing command"))
    }

    @Test func cliRejectsUnknownCommand() throws {
        let result = try Self.runCLI(["frobnicate", "--service-name", "com.hkdfguard.tests.cli.unknown.command"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("unknown command"))
    }

    @Test func cliRejectsPositionalKeyFilePath() throws {
        // The key file path used to be positional; a caller on the old
        // syntax must get told exactly what changed.
        let keyFilePath = Self.makeTempFilePath()
        let result = try Self.runCLI(["wrap", keyFilePath, "--service-name", "com.hkdfguard.tests.cli.positional.path", "--dek-stdin"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("--key-file-path"), "stderr: \(result.stderr)")
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test func cliProvisionRejectsWrapOnlyFlags() throws {
        let result = try Self.runCLI(["provision", "--service-name", "com.hkdfguard.tests.cli.provision.extra", "--dek-stdin"])
        #expect(result.exitCode == 2)
        #expect(result.stderr.contains("unrecognized argument"))
    }

    // MARK: - Data-protection mode: the bundled CLI provisions, the entitled host unwraps

    /// The bundled build of the CLI (`hkdfguard-v1-initialize-app` target):
    /// the same main.swift inside an app bundle with an embedded provisioning
    /// profile and the shared `com.hkdfguard.keys` access group, which is
    /// what lets it run in data-protection mode. Built into the same
    /// products directory as the host app this bundle runs in.
    private static let bundledCLIPath = Bundle.main.bundleURL
        .deletingLastPathComponent()
        .appendingPathComponent("hkdfguard-v1-initialize.app/Contents/MacOS/hkdfguard-v1-initialize")
        .path

    private static let dataProtectionRoundTripEnabled =
        hkdfguardKeychainMode != .legacy && FileManager.default.fileExists(atPath: bundledCLIPath)

    /// Deletes a KEK item from the keychain *this process's mode* uses --
    /// the only way to clean up a data-protection item, which the
    /// legacy-only `security` tool used by `deleteKEK` cannot see.
    private static func deleteKEKInProcess(service: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service.lowercased(),
            kSecAttrAccount as String: hkdfguardKeychainAccount,
            kSecAttrSynchronizable as String: false,
        ]
        if case .dataProtection(let accessGroup) = hkdfguardKeychainMode {
            query[kSecUseDataProtectionKeychain as String] = true
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        SecItemDelete(query as CFDictionary)
    }

    @Test(.enabled(if: dataProtectionRoundTripEnabled && SecureEnclave.isAvailable, "requires the entitled HkdfGuardTestHost and the bundled CLI (data-protection mode)"))
    func bundledCliProvisionsAndWrapsInDataProtectionModeAndEntitledHostUnwraps() throws {
        // The production topology end to end, with no interactive prompt:
        // a Team-signed, entitled provisioner (the bundled CLI) creates the
        // KEK and wraps a DEK in the shared access group; a different
        // Team-signed, entitled process (this host) unwraps it through the
        // library. securityd grants the access from the signed identities
        // alone -- the thing legacy mode can only do after a human clicks
        // Allow.
        let service = "com.hkdfguard.tests.cli.dataprotection.roundtrip"
        defer { Self.deleteKEKInProcess(service: service) }
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }
        let cli = URL(fileURLWithPath: Self.bundledCLIPath)

        let provision = try Self.run(cli, ["provision", "--service-name", service])
        #expect(provision.exitCode == 0, "provision failed: \(provision.stderr)")
        #expect(provision.stdout.contains("keychain: data-protection"), "stdout: \(provision.stdout)")

        let dek = Self.randomDEK()
        let wrap = try Self.run(
            cli,
            ["wrap", "--key-file-path", keyFilePath, "--service-name", service, "--dek-stdin"],
            stdin: Self.base64Stdin(dek)
        )
        #expect(wrap.exitCode == 0, "wrap failed: \(wrap.stderr)")
        #expect(wrap.stdout.contains("keychain: data-protection"), "stdout: \(wrap.stdout)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        #expect(wrapped.count == 156)
        let recovered = Self.unwrapInApplicationCode(wrapped, service: service)
        #expect(recovered.status == 0, "unwrap in the entitled host failed with \(recovered.status)")
        #expect(recovered.dek == dek)

        // Disjoint keychains: the legacy login keychain (what the bare CLI
        // and the `security` tool see) must have no trace of this KEK.
        #expect(!Self.kekItemExists(service: service))
    }
}
