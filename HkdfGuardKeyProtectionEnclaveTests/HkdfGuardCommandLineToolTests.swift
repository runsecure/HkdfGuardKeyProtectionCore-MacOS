//
//  HkdfGuardCommandLineToolTests.swift
//  HkdfGuardKeyProtectionEnclaveTests
//

import Testing
import Foundation
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
/// `HkdfGuardKeyProtectionEnclaveWrapUnwrapTests`.
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
        .appendingPathComponent("build/Release/HkdfGuard.Kms.P256Sha512AesGcm256.dylib")
        .path

    private static let cliPackageDir = repoRoot
        .appendingPathComponent("hkdfguard-v1-initialize")

    private static let cliExecutablePath = repoRoot
        .appendingPathComponent("hkdfguard-v1-initialize/.build/release/hkdfguard-v1-initialize")
        .path

    private struct ToolBuildError: Error, CustomStringConvertible {
        let description: String
    }

    /// Runs `arguments` to completion and returns its exit code plus
    /// captured stdout/stderr. Output is read only after the child exits,
    /// which is safe here because every process this suite launches
    /// writes at most a few lines — nowhere near a pipe buffer's capacity
    /// — so there's no risk of the classic "child blocks writing, parent
    /// blocks reading, deadlock" ordering issue that pattern has in
    /// general.
    @discardableResult
    private static func run(_ executableURL: URL, _ arguments: [String], currentDirectory: URL? = nil) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        if let currentDirectory {
            process.currentDirectoryURL = currentDirectory
        }
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
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
    private static func runCLI(_ arguments: [String]) throws -> (exitCode: Int32, stdout: String, stderr: String) {
        try ensureCLIBuilt()
        return try run(URL(fileURLWithPath: cliExecutablePath), arguments)
    }

    // MARK: - Helpers shared with the round-trip/tamper tests

    private static func randomDEK() -> [UInt8] {
        (0..<dekLength).map { _ in UInt8.random(in: .min ... .max) }
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
        process.arguments = ["delete-generic-password", "-s", service, "-a", hkdfguardKeychainAccount]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
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

    @Test(.enabled(if: interactiveKeychainAccessEnabled, interactiveKeychainAccessComment))
    func cliWrappedDekIsRecoveredByApplicationCode() throws {
        let service = "com.hkdfguard.tests.cli.roundtrip"
        // The CLI derives its actual KEK service string as
        // "<service-name>.<material-identifier>" — see main.swift's `run`
        // — so that's the item that must be cleaned up, not the bare name.
        defer { Self.deleteKEK(service: "\(service).1") }

        let dek = Self.randomDEK()
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", service,
            "--dek", Data(dek).base64EncodedString()
        ])
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")
        #expect(FileManager.default.fileExists(atPath: keyFilePath))

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: "\(service).1")
        #expect(recovered.status == 0)
        #expect(recovered.dek == dek)
    }

    @Test func cliWrappedFileHasExpectedLengthAndPermissions() throws {
        let service = "com.hkdfguard.tests.cli.file-attributes"
        defer { Self.deleteKEK(service: "\(service).1") }

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", service,
            "--dek", Data(Self.randomDEK()).base64EncodedString()
        ])
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")

        let attributes = try FileManager.default.attributesOfItem(atPath: keyFilePath)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue
        #expect(permissions == 0o640)

        let wrapped = try Data(contentsOf: URL(fileURLWithPath: keyFilePath))
        #expect(wrapped.count == 124) // 64-byte ephemeral pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag
    }

    @Test(.enabled(if: interactiveKeychainAccessEnabled, interactiveKeychainAccessComment))
    func differentMaterialIdentifiersAreIsolatedThroughTheRealCLI() throws {
        // Confirms the "<service-name>.<material-identifier>" convention
        // is actually wired correctly end to end through the CLI's own
        // argument handling, not just asserted in a comment — application
        // code unwrapping under the wrong material identifier must fail.
        let service = "com.hkdfguard.tests.cli.material-isolation"
        defer {
            Self.deleteKEK(service: "\(service).1")
            Self.deleteKEK(service: "\(service).2")
        }

        let dek = Self.randomDEK()
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", service,
            "--dek", Data(dek).base64EncodedString()
        ])
        #expect(result.exitCode == 0, "CLI failed: \(result.stderr)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))

        let wrongMaterial = Self.unwrapInApplicationCode(wrapped, service: "\(service).2")
        #expect(wrongMaterial.status != 0)

        let rightMaterial = Self.unwrapInApplicationCode(wrapped, service: "\(service).1")
        #expect(rightMaterial.status == 0)
        #expect(rightMaterial.dek == dek)
    }

    // MARK: - File handling: refuses to clobber, --force overwrites correctly

    @Test(.enabled(if: interactiveKeychainAccessEnabled, interactiveKeychainAccessComment))
    func cliRefusesToOverwriteWithoutForce() throws {
        let service = "com.hkdfguard.tests.cli.no-overwrite"
        defer { Self.deleteKEK(service: "\(service).1") }

        let firstDek = Self.randomDEK()
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let firstResult = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", service,
            "--dek", Data(firstDek).base64EncodedString()
        ])
        #expect(firstResult.exitCode == 0, "CLI failed: \(firstResult.stderr)")

        let secondResult = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", service,
            "--dek", Data(Self.randomDEK()).base64EncodedString()
        ])
        #expect(secondResult.exitCode != 0)

        // The original file, and the DEK it wraps, must be untouched.
        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: "\(service).1")
        #expect(recovered.status == 0)
        #expect(recovered.dek == firstDek)
    }

    @Test(.enabled(if: interactiveKeychainAccessEnabled, interactiveKeychainAccessComment))
    func cliForceOverwritesWithNewDek() throws {
        let service = "com.hkdfguard.tests.cli.force-overwrite"
        defer { Self.deleteKEK(service: "\(service).1") }

        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let firstResult = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", service,
            "--dek", Data(Self.randomDEK()).base64EncodedString()
        ])
        #expect(firstResult.exitCode == 0, "CLI failed: \(firstResult.stderr)")

        let secondDek = Self.randomDEK()
        let secondResult = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", service,
            "--dek", Data(secondDek).base64EncodedString(),
            "--force"
        ])
        #expect(secondResult.exitCode == 0, "CLI --force failed: \(secondResult.stderr)")

        let wrapped = try Array(Data(contentsOf: URL(fileURLWithPath: keyFilePath)))
        let recovered = Self.unwrapInApplicationCode(wrapped, service: "\(service).1")
        #expect(recovered.status == 0)
        #expect(recovered.dek == secondDek)
    }

    // MARK: - Input validation, via the real CLI's own argument handling

    @Test func cliRejectsNonBase64Dek() throws {
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", "com.hkdfguard.tests.cli.bad-dek",
            "--dek", "not-valid-base64!!"
        ])
        #expect(result.exitCode == 1)
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test func cliRejectsWrongLengthDek() throws {
        let keyFilePath = Self.makeTempFilePath()
        defer { try? FileManager.default.removeItem(atPath: keyFilePath) }

        let result = try Self.runCLI([
            keyFilePath,
            "--material-identifier", "1",
            "--service-name", "com.hkdfguard.tests.cli.short-dek",
            "--dek", Data([UInt8](repeating: 0, count: 16)).base64EncodedString()
        ])
        #expect(result.exitCode == 1)
        #expect(!FileManager.default.fileExists(atPath: keyFilePath))
    }

    @Test func cliRejectsMissingRequiredArguments() throws {
        let result = try Self.runCLI(["--service-name", "com.hkdfguard.tests.cli.missing-args"])
        #expect(result.exitCode == 2) // argument-parsing failure, distinct from a runtime failure
    }

    @Test func cliPrintsUsageOnHelp() throws {
        let result = try Self.runCLI(["--help"])
        #expect(result.exitCode == 0)
        #expect(result.stderr.localizedCaseInsensitiveContains("usage"))
    }
}
