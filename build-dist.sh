#!/usr/bin/env bash
# Builds the Release dylib and the hkdfguard-v1-initialize CLI, then
# collects the artifacts a downstream consumer actually needs (the dylib,
# its C header, and the CLI executable) into dist/.
#
# Usage: ./build-dist.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"

echo "==> Building HkdfGuardKeyProtectionEnclaveDylib (Release)"
xcodebuild -project "$ROOT/HkdfGuardKeyProtectionEnclave.xcodeproj" \
    -target HkdfGuardKeyProtectionEnclaveDylib \
    -configuration Release \
    build

echo "==> Building hkdfguard-v1-initialize (release)"
swift build -c release --package-path "$ROOT/hkdfguard-v1-initialize"

echo "==> Assembling $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

# Globbed rather than hardcoded: the dylib's PRODUCT_NAME has already
# changed once during this project's development, and this only needs to
# find the one dylib that build produces, not police its name.
cp "$ROOT"/build/Release/*.dylib "$DIST/"
cp "$ROOT/HkdfGuardKeyProtectionEnclave/HkdfGuardKeyProtectionEnclave.h" "$DIST/"
cp "$ROOT/hkdfguard-v1-initialize/.build/release/hkdfguard-v1-initialize" "$DIST/"

echo "==> Making dist/hkdfguard-v1-initialize self-contained"
# As linked (see hkdfguard-v1-initialize/Package.swift), the CLI only
# finds the dylib via an -rpath baked in as this build machine's absolute
# build/Release path -- fine locally, useless once dist/ is copied
# anywhere else. The dylib's own install_name is already the relocatable
# "@rpath/<name>.dylib" (DYLIB_INSTALL_NAME_BASE = @rpath in the Xcode
# target), so the only thing the CLI itself needs is an rpath entry that
# resolves relative to wherever it's actually run from: swap the
# absolute one for "@executable_path" (dyld's token for "the directory
# the running binary lives in"), so it looks right next to itself.
CLI_DIST="$DIST/hkdfguard-v1-initialize"
install_name_tool -delete_rpath "$ROOT/build/Release" "$CLI_DIST"
install_name_tool -add_rpath "@executable_path" "$CLI_DIST"
# install_name_tool invalidates whatever signature the linker produced;
# re-sign ad hoc (no identity, no entitlements needed for a bare CLI) so
# dyld/Gatekeeper will still run it, including on Apple Silicon, where an
# unsigned binary simply won't launch at all.
codesign --sign - --force "$CLI_DIST"

echo "==> Done:"
ls -la "$DIST"
