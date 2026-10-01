#!/usr/bin/env bash
# One-time developer setup: provisions a persistent Secure Enclave KEK in
# the *data-protection* keychain (not the legacy login keychain), under a
# fixed, well-known service name, so hosted unit tests
# (HkdfGuardKeyProtectionEnclaveTests-Hosted / HkdfGuardTestHost.app) have
# an already-provisioned key to test against without every run needing to
# provision one itself.
#
# What "already imported" means here: this KEK's opaque data representation
# is stored as a real keychain item under the shared com.hkdfguard.keys
# access group, exactly as production provisioning would leave it -- there
# is no separate "import" step or key file; provisioning *is* the import,
# because the private key material never leaves the Secure Enclave to begin
# with (see HkdfGuardKeyProtectionEnclave.swift). This script just runs
# that provisioning once, signed, so it doesn't have to happen inside every
# test invocation.
#
# How: builds the `hkdfguard-v1-initialize-app` target (the bundled,
# Team-signed, hardened-runtime build of the CLI, entitled for
# com.hkdfguard.keys -- see HkdfGuardKeyProtectionEnclave.xcodeproj and
# hkdfguard-v1-initialize/hkdfguard-v1-initialize.entitlements) and runs its
# `provision` command once. That entitlement is what puts the KEK in the
# data-protection keychain instead of the legacy one (see "Keychain modes"
# in README.md) -- running the bare SwiftPM CLI here would provision into
# the *legacy* keychain instead, which is not what this script is for.
#
# Idempotent: hkdfguard_create_kek (what `provision` calls) is a no-op if
# the KEK already exists, so re-running this script is always safe and
# leaves the same KEK in place.
#
# Requirements (one-time, per developer machine, not handled by this
# script): this Mac must be registered as a device in the Apple developer
# account so Xcode can mint a Mac App Development provisioning profile for
# the entitled app targets -- without a profile, a process requesting
# keychain-access-groups is killed by AMFI at launch, entitlement or not.
# See README.md's "Tests" section for the exact steps. This script detects
# that failure and prints the same instructions rather than a raw
# xcodebuild error dump.
#
# Usage:
#   ./setup-hosted-test-kek.sh                # provisions the default fixture service
#   ./setup-hosted-test-kek.sh --service-name com.example.my.fixture
#   ./setup-hosted-test-kek.sh --configuration Release
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$ROOT/HkdfGuardKeyProtectionEnclave.xcodeproj"
TARGET="hkdfguard-v1-initialize-app"

# A fixed, well-known service name for the persistent fixture KEK -- ASCII
# letters/digits/'.' only, matching the library's own charset rule (see
# validServiceName in HkdfGuardKeyProtectionEnclave.swift; no '-' or '_').
# Hosted tests that want to consume an already-provisioned key, rather than
# provisioning their own, reference this same name.
SERVICE_NAME="com.hkdfguard.fixture.hostedtests"
CONFIGURATION="Debug"

while [ $# -gt 0 ]; do
    case "$1" in
        --service-name)
            SERVICE_NAME="${2:?--service-name requires a value}"
            shift 2
            ;;
        --configuration)
            CONFIGURATION="${2:?--configuration requires a value}"
            shift 2
            ;;
        -h|--help)
            sed -n '2,43p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unrecognized argument: $1" >&2
            exit 2
            ;;
    esac
done

echo "==> Building $TARGET ($CONFIGURATION)"
BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/hkdfguard-setup-kek.XXXXXX")"
trap 'rm -f "$BUILD_LOG"' EXIT

if ! xcodebuild -project "$PROJECT" \
        -target "$TARGET" \
        -configuration "$CONFIGURATION" \
        -allowProvisioningUpdates \
        build >"$BUILD_LOG" 2>&1; then
    if grep -qE "isn't registered in your developer account|No profiles for" "$BUILD_LOG"; then
        cat >&2 <<'EOF'

error: this Mac (or its App ID) is not yet set up for automatic
provisioning, so the entitled hkdfguard-v1-initialize-app target cannot be
signed. This is a one-time, per-developer-machine step this script cannot
do for you:

  1. Find this Mac's Provisioning UDID:
       system_profiler SPHardwareDataType | grep 'Provisioning UDID'
  2. Register it as a device: developer.apple.com -> Certificates,
     Identifiers & Profiles -> Devices -> + -> macOS -> paste the UDID.
     (Or open the project in Xcode, select the HkdfGuardTestHost or
     hkdfguard-v1-initialize-app target's Signing & Capabilities tab --
     Xcode offers to register the device for you.)
  3. Re-run this script.
EOF
        echo "Full build log kept at: $BUILD_LOG" >&2
        trap - EXIT
        exit 1
    fi
    echo "error: build failed; see log below" >&2
    cat "$BUILD_LOG" >&2
    exit 1
fi

# CONFIGURATION_BUILD_DIR, not an assumed "build/$CONFIGURATION" path: this
# target has no BUILD_DIR override, so it resolves through DerivedData
# unless the project's default has been changed.
BUILT_PRODUCTS_DIR="$(xcodebuild -project "$PROJECT" -target "$TARGET" -configuration "$CONFIGURATION" \
    -showBuildSettings 2>/dev/null | awk -F' = ' '/ CONFIGURATION_BUILD_DIR /{print $2; exit}')"
CLI="$BUILT_PRODUCTS_DIR/hkdfguard-v1-initialize.app/Contents/MacOS/hkdfguard-v1-initialize"

if [ ! -x "$CLI" ]; then
    echo "error: build reported success but $CLI is not there -- looked in: $BUILT_PRODUCTS_DIR" >&2
    exit 1
fi

echo "==> Provisioning KEK for service \"$SERVICE_NAME\""
"$CLI" provision --service-name "$SERVICE_NAME"

echo
echo "Done. Hosted tests (HkdfGuardKeyProtectionEnclaveTests-Hosted) can now"
echo "reference service \"$SERVICE_NAME\" as an already-provisioned,"
echo "data-protection-keychain KEK. This is a persistent fixture -- re-run"
echo "this script any time (it's a no-op if the KEK already exists). To"
echo "remove it, use this same bundled CLI (Keychain Access cannot see"
echo "data-protection items):"
echo "  \"$CLI\" retire --service-name \"$SERVICE_NAME\" --fingerprint <fingerprint above>"
