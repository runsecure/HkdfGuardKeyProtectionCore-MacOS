// swift-tools-version:5.9
import Foundation
import PackageDescription

// This package builds one executable, `hkdfguard-v1-initialize`, that links
// directly against the sibling Xcode project's already-built
// HkdfGuard.Kms.MacOS.v1.dylib (the HkdfGuardKeyProtectionEnclaveDylib
// target) and calls into it purely through its stable C ABI
// (`hkdfguard_wrap_dek`) -- the same interface any other-language caller
// uses, matching this project's Linux equivalent
// (HkdfGuardKeyProtectionCore-Linux/src/bin/hkdfguard-v1-initialize.rs).
//
// Build the library first:
//   xcodebuild -project ../HkdfGuardKeyProtectionEnclave.xcodeproj \
//       -target HkdfGuardKeyProtectionEnclaveDylib -configuration Release build
// then build/run this tool from anywhere:
//   swift build --package-path <this-directory> -c release
//   <this-directory>/.build/release/hkdfguard-v1-initialize --help
//
// The dylib's own `install_name` is `@rpath/HkdfGuard.Kms.MacOS.v1.dylib`
// (see its build settings' DYLIB_INSTALL_NAME_BASE), so the executable needs
// an explicit -rpath pointing at the directory it actually lives in to
// resolve it at *run* time, not just link time. That directory is computed
// from `#filePath` (this manifest's own absolute path, resolved fresh by
// SwiftPM on every build) rather than hardcoded or left relative -- a
// relative -rpath is resolved by dyld against the *calling process's
// current working directory* at launch, not against where this executable
// lives on disk, so it would only work when invoked from inside this exact
// package directory. An absolute path sidesteps that entirely: the tool
// then runs correctly regardless of the caller's cwd, exactly like a
// normal installed command-line tool should.
let hkdfguardDylibDir = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent() // this package's own directory
    .appendingPathComponent("../build/Release")
    .standardizedFileURL
    .path
let hkdfguardDylibPath = "\(hkdfguardDylibDir)/HkdfGuard.Kms.MacOS.v1.dylib"

let package = Package(
    name: "hkdfguard-v1-initialize",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "hkdfguard-v1-initialize",
            linkerSettings: [
                // The dylib's actual filename has no "lib" prefix and
                // contains dots (see the Xcode target's EXECUTABLE_PREFIX
                // override), so a normal `-l<name>` flag (which always
                // assumes and prepends "lib") can't find it -- passing the
                // literal path straight to the linker via -Xlinker sidesteps
                // that entirely, exactly like handing ld a plain .o file.
                .unsafeFlags([
                    "-Xlinker", hkdfguardDylibPath,
                    "-Xlinker", "-rpath", "-Xlinker", hkdfguardDylibDir,
                ])
            ]
        )
    ]
)
