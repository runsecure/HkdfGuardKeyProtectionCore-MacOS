// Host application for HkdfGuardKeyProtectionEnclaveTests.
//
// Exists for one reason: the data-protection keychain (see `KeychainMode`
// in HkdfGuardKeyProtectionEnclave.swift) is only available to a process
// carrying a `keychain-access-groups` entitlement, which on macOS means a
// Team-signed app bundle with an embedded provisioning profile. The plain
// `xctest` agent has no such entitlement, so tests hosted by it can only
// ever exercise the legacy login-keychain path. Hosting the test bundle in
// this app -- entitled for the shared `com.hkdfguard.keys` group, the same
// group the bundled CLI uses -- makes the whole suite run in
// data-protection mode, including the cross-process provision (CLI) ->
// unwrap (this process) round trip with no interactive prompt.
//
// No UI, no Dock icon (LSUIElement), no hardened runtime (a test fixture,
// and Xcode's test injection relies on DYLD environment variables the
// hardened runtime disables). It simply runs an event loop until the test
// runner is done with it.

import AppKit

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
app.run()
