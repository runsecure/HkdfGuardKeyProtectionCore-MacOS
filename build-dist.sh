#!/usr/bin/env bash
# Builds the Release dylib and the hkdfguard-v1-initialize CLI for each
# supported architecture, signs both with the hardened runtime, verifies
# them, and collects what a downstream consumer needs (dylib, C header, CLI,
# SHA256SUMS) into dist/<rid>/ -- one folder per .NET-style runtime
# identifier: osx-x64 and osx-arm64.
#
# Usage: ./build-dist.sh
#
# Everything is assembled in a temporary staging directory and only moved
# into place as dist/ once every build, signature, and check has passed, so
# a failure part-way through never leaves an empty or half-populated dist/.
#
# Signing uses a secure timestamp (--timestamp), which contacts Apple's
# timestamp server: this script needs network access to complete.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
CLI_PKG="$ROOT/hkdfguard-v1-initialize"
DYLIB_NAME="HkdfGuard.Kms.MacOS.v1.dylib"
HEADER="$ROOT/HkdfGuardKeyProtectionEnclave/HkdfGuardKeyProtectionEnclave.h"

# Signing identity for every artifact below. Override with
# HKDFGUARD_SIGN_IDENTITY=... (e.g. a "Developer ID Application" identity for
# distribution outside your own team) without editing this script.
SIGN_IDENTITY="${HKDFGUARD_SIGN_IDENTITY:-Apple Development}"

# --options runtime: hardened runtime. For the CLI this disables the DYLD_*
# environment variables (DYLD_LIBRARY_PATH was demonstrated to silently
# redirect which dylib the CLI loads) and turns on library validation, so
# it will only load dylibs signed by the same Team ID or by Apple -- which
# is why the dylib next to it is signed with the same identity, here, by
# this script, rather than relying on whatever the Xcode target's own
# signing step happened to do (ENABLE_HARDENED_RUNTIME is off in the
# project, and a plain `codesign --sign` does not add it).
CODESIGN_FLAGS=(--force --options runtime --timestamp --sign "$SIGN_IDENTITY")

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/hkdfguard-dist.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

fail() { echo "error: $*" >&2; exit 1; }

# Asserts that a Mach-O file is a thin binary for exactly one architecture.
assert_arch() {
    local file="$1" expected="$2" actual
    actual="$(lipo -archs "$file")"
    [ "$actual" = "$expected" ] || fail "$file is built for '$actual', expected '$expected'"
}

# Asserts a signature verifies strictly and carries the hardened-runtime
# flag and a secure timestamp.
#
# Tool output is captured into a variable before grepping, here and in
# every check below: piping a tool straight into `grep -q` lets grep exit
# on its first match, the tool then dies of SIGPIPE writing the rest of its
# output, and `set -o pipefail` reports that as a failed pipeline -- a
# false failure (or, for a negated check, a false pass).
assert_signed() {
    local file="$1" info
    codesign --verify --strict --verbose=1 "$file" \
        || fail "$file: signature does not verify"
    info="$(codesign -dv "$file" 2>&1)"
    grep -q 'flags=0x10000(runtime)' <<<"$info" \
        || fail "$file: hardened runtime flag missing"
    grep -q '^Timestamp=' <<<"$info" \
        || fail "$file: secure timestamp missing"
}

# build_arch <xcode-arch> <rid>
#   xcode-arch: value for xcodebuild ARCHS / swift build --arch (x86_64, arm64)
#   rid:        dist/ subfolder name (osx-x64, osx-arm64)
build_arch() {
    local arch="$1" rid="$2"
    local build_dir="$ROOT/build-$arch"
    local dylib_dir="$build_dir/Release"
    local out="$STAGE/$rid"
    local scratch="$CLI_PKG/.build-$arch"

    echo
    echo "==================== $rid ($arch) ===================="
    mkdir -p "$out"

    echo "==> Building $DYLIB_NAME for $arch (Release) into $build_dir"
    xcodebuild -project "$ROOT/HkdfGuardKeyProtectionEnclave.xcodeproj" \
        -target HkdfGuardKeyProtectionEnclaveDylib \
        -configuration Release \
        ARCHS="$arch" ONLY_ACTIVE_ARCH=NO \
        BUILD_DIR="$build_dir" \
        build
    [ -f "$dylib_dir/$DYLIB_NAME" ] || fail "expected $dylib_dir/$DYLIB_NAME after the xcodebuild above"

    echo "==> Building hkdfguard-v1-initialize for $arch (release)"
    # Distinct --scratch-path per architecture: SwiftPM caches the evaluated
    # manifest (and therefore the linker flags derived from
    # HKDFGUARD_DYLIB_DIR) per scratch directory.
    HKDFGUARD_DYLIB_DIR="$dylib_dir" swift build -c release \
        --arch "$arch" \
        --package-path "$CLI_PKG" \
        --scratch-path "$scratch"
    local cli_bin_dir
    cli_bin_dir="$(HKDFGUARD_DYLIB_DIR="$dylib_dir" swift build -c release \
        --arch "$arch" \
        --package-path "$CLI_PKG" \
        --scratch-path "$scratch" \
        --show-bin-path)"
    [ -f "$cli_bin_dir/hkdfguard-v1-initialize" ] || fail "expected CLI at $cli_bin_dir/hkdfguard-v1-initialize"

    echo "==> Assembling $out"
    cp "$dylib_dir/$DYLIB_NAME" "$out/"
    cp "$HEADER" "$out/"
    cp "$cli_bin_dir/hkdfguard-v1-initialize" "$out/"

    echo "==> Making $rid/hkdfguard-v1-initialize self-contained"
    # As linked (see Package.swift), the CLI finds the dylib via an -rpath
    # baked in as this machine's absolute per-arch build directory -- fine
    # locally, useless once dist/ is copied anywhere else. The dylib's own
    # install_name is the relocatable "@rpath/<name>.dylib", so the CLI
    # only needs an rpath that resolves relative to itself:
    # @executable_path, i.e. "the directory this binary lives in".
    local cli="$out/hkdfguard-v1-initialize"
    install_name_tool -delete_rpath "$dylib_dir" "$cli"
    install_name_tool -add_rpath "@executable_path" "$cli"
    local rpaths
    rpaths="$(otool -l "$cli" | grep -A2 LC_RPATH || true)"
    if grep -q "path $dylib_dir" <<<"$rpaths"; then
        fail "$cli still carries the absolute build rpath $dylib_dir"
    fi
    grep -q 'path @executable_path' <<<"$rpaths" \
        || fail "$cli lacks the @executable_path rpath"

    echo "==> Signing (hardened runtime, timestamped) with: $SIGN_IDENTITY"
    # install_name_tool invalidated the CLI's linker signature; and the
    # dylib is re-signed here too so both carry identical options and
    # identity regardless of the Xcode target's own signing settings.
    codesign "${CODESIGN_FLAGS[@]}" "$out/$DYLIB_NAME"
    codesign "${CODESIGN_FLAGS[@]}" "$cli"

    echo "==> Verifying $rid"
    assert_arch "$out/$DYLIB_NAME" "$arch"
    assert_arch "$cli" "$arch"
    assert_signed "$out/$DYLIB_NAME"
    assert_signed "$cli"
    local links
    links="$(otool -L "$cli")"
    grep -q "@rpath/$DYLIB_NAME" <<<"$links" \
        || fail "$cli does not reference @rpath/$DYLIB_NAME"

    # Smoke test, host architecture only: --help must launch, which means
    # dyld resolved the dylib next to the binary via @executable_path AND
    # library validation (hardened runtime) accepted its signature.
    if [ "$(uname -m)" = "$arch" ]; then
        echo "==> Smoke test: $cli --help"
        local help
        help="$("$cli" --help 2>&1)" || fail "$cli --help exited non-zero: $help"
        grep -qi usage <<<"$help" || fail "$cli --help did not print usage"
    else
        echo "==> (skipping launch smoke test: host is $(uname -m), artifact is $arch)"
    fi

    echo "==> Writing $rid/SHA256SUMS"
    (cd "$out" && shasum -a 256 "$DYLIB_NAME" "$(basename "$HEADER")" hkdfguard-v1-initialize > SHA256SUMS)
}

build_arch x86_64 osx-x64
build_arch arm64  osx-arm64

echo
echo "==> All builds and checks passed; installing into $DIST"
rm -rf "$DIST"
mv "$STAGE" "$DIST"
trap - EXIT

echo "==> Done:"
find "$DIST" -type f | sort | while read -r f; do
    printf '%-70s %s\n' "${f#"$ROOT"/}" "$(lipo -archs "$f" 2>/dev/null || echo '-')"
done
echo
cat "$DIST"/osx-*/SHA256SUMS
