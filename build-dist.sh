#!/usr/bin/env bash
# Builds the Release dylib and the hkdfguard-v1-initialize CLI, then
# collects the artifacts a downstream consumer actually needs (the dylib,
# its C header, and the CLI executable) into dist/.
#
# Usage: ./build-dist.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"

echo "==> Assembling $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

ARCH="$DIST/osx-x64"

echo "==> Assembling $ARCH"
rm -rf "$ARCH"
mkdir -p "$ARCH"

# Signing identity used for both artifacts below. The dylib target's own
# CODE_SIGN_STYLE=Automatic already resolves to this same identity on its
# own; the CLI needs it passed explicitly (see the codesign call further
# down), so both are driven from one place here. Override with
# HKDFGUARD_SIGN_IDENTITY=... to sign with something else (e.g. a
# "Developer ID Application" identity for wider distribution) without
# editing this script.
SIGN_IDENTITY="${HKDFGUARD_SIGN_IDENTITY:-Apple Development}"

echo "==> Building HkdfGuardKeyProtectionEnclaveDylib (Release)"
xcodebuild -project "$ROOT/HkdfGuardKeyProtectionEnclave.xcodeproj" \
    -target HkdfGuardKeyProtectionEnclaveDylib \
    -configuration Release \
    ARCHS=x86_x64 \
    BUILD_DIR="$ROOT/build-x64" \
    build

echo "==> Building hkdfguard-v1-initialize x64 (release)"
swift build -c release --package-path "$ROOT/hkdfguard-v1-initialize"

# Globbed rather than hardcoded: the dylib's PRODUCT_NAME has already
# changed once during this project's development, and this only needs to
# find the one dylib that build produces, not police its name.
cp "$ROOT"/build/Release/*.dylib "$ARCH/"
cp "$ROOT/HkdfGuardKeyProtectionEnclave/HkdfGuardKeyProtectionEnclave.h" "$ARCH/"
cp "$ROOT/hkdfguard-v1-initialize/.build/release/hkdfguard-v1-initialize" "$ARCH/"

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

CLI_DIST="$ARCH/hkdfguard-v1-initialize"
install_name_tool -delete_rpath "$ROOT/build/Release" "$CLI_DIST"
install_name_tool -add_rpath "@executable_path" "$CLI_DIST"
# install_name_tool invalidates whatever signature the linker produced;
# re-sign with the real identity above (not ad hoc) so what ends up in
# dist/ is an actually-signed build, matching the dylib next to it.
codesign --sign "$SIGN_IDENTITY" --force "$CLI_DIST"

echo "==> osx-x64 Done:"

echo "==========> Now for arm64 <============"

ARCH="$DIST/osx-arm64"

echo "==> Assembling $ARCH"
rm -rf "$ARCH"
mkdir -p "$ARCH"

# Signing identity used for both artifacts below. The dylib target's own
# CODE_SIGN_STYLE=Automatic already resolves to this same identity on its
# own; the CLI needs it passed explicitly (see the codesign call further
# down), so both are driven from one place here. Override with
# HKDFGUARD_SIGN_IDENTITY=... to sign with something else (e.g. a
# "Developer ID Application" identity for wider distribution) without
# editing this script.
SIGN_IDENTITY="${HKDFGUARD_SIGN_IDENTITY:-Apple Development}"

echo "==> Building HkdfGuardKeyProtectionEnclaveDylib (Release)"
xcodebuild -project "$ROOT/HkdfGuardKeyProtectionEnclave.xcodeproj" \
    -target HkdfGuardKeyProtectionEnclaveDylib \
    -configuration Release \
    ARCHS=arm64 \
    BUILD_DIR="$ROOT/build-arm64" \
    build

echo "==> Building hkdfguard-v1-initialize arm64 (release)"
swift build -c release --package-path "$ROOT/hkdfguard-v1-initialize"

# Globbed rather than hardcoded: the dylib's PRODUCT_NAME has already
# changed once during this project's development, and this only needs to
# find the one dylib that build produces, not police its name.
cp "$ROOT"/build/Release/*.dylib "$ARCH/"
cp "$ROOT/HkdfGuardKeyProtectionEnclave/HkdfGuardKeyProtectionEnclave.h" "$ARCH/"
cp "$ROOT/hkdfguard-v1-initialize/.build/release/hkdfguard-v1-initialize" "$ARCH/"

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

CLI_DIST="$ARCH/hkdfguard-v1-initialize"
install_name_tool -delete_rpath "$ROOT/build/Release" "$CLI_DIST"
install_name_tool -add_rpath "@executable_path" "$CLI_DIST"
# install_name_tool invalidates whatever signature the linker produced;
# re-sign with the real identity above (not ad hoc) so what ends up in
# dist/ is an actually-signed build, matching the dylib next to it.
codesign --sign "$SIGN_IDENTITY" --force "$CLI_DIST"

echo "==> osx-arm64 Done:"

echo "==> Done:"
ls -la "$DIST"
