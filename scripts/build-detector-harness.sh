#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${THEOS:?THEOS must point to Theos}"

# macOS/Xcode compiles the new arm64e ABI itself; a Linux cross build needs the
# modern toolchain and IS_NEW_ABI=1 (mirrors build.sh modern_args). m() appends
# these to every sub-make so the rootless harness links new-ABI, not old.
ABI_ARGS=()
if [ "$(uname -s)" = Linux ]; then
    tc=${NEWABI_TOOLCHAIN:-$THEOS/toolchain/modern/linux/iphone}
    [ -x "$tc/bin/clang" ] || { echo "missing new-ABI toolchain: $tc" >&2; exit 1; }
    ABI_ARGS=("SDKBINPATH=$tc/bin" "IS_NEW_ABI=1")
fi
m() { make "$@" ${ABI_ARGS[@]+"${ABI_ARGS[@]}"}; }

"$ROOT/scripts/fetch-detector-sdks.sh" iossecuritysuite
"$ROOT/scripts/fetch-detector-sdks.sh" jailbreakdetector
"$ROOT/scripts/fetch-detector-sdks.sh" securitytoolkit
"$ROOT/scripts/fetch-detector-sdks.sh" dtt
"$ROOT/scripts/fetch-detector-sdks.sh" freerasp
"$ROOT/scripts/fetch-detector-sdks.sh" roothider
"$ROOT/scripts/fetch-detector-sdks.sh" bat
"$ROOT/scripts/fetch-detector-sdks.sh" safetynet
"$ROOT/scripts/fetch-detector-sdks.sh" devicesecuritykit
"$ROOT/scripts/fetch-detector-sdks.sh" jailmonkey
m -C "$ROOT/Shadow.framework" THEOS_PACKAGE_SCHEME=rootless TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache
m -C "$ROOT/DetectorRunners/IOSSecuritySuite" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/JailbreakDetector" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/SecurityToolkit" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/DTTJailbreakDetection" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/FreeRASP" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/Roothider" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/BATJailbreakGuard" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/SafetyNet" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/DeviceSecurityKit" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/DetectorRunners/JailMonkey" stage THEOS_PACKAGE_SCHEME=rootless
m -C "$ROOT/tools/dyldprobe" stage THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    THEOS_LIBRARY_PATH=/tmp/shadow-dyldprobe-lib \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache
m -C "$ROOT/ShadowHarness" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    THEOS_LIBRARY_PATH="$ROOT/Shadow.framework/.theos/obj/debug" INCLUDE_DETECTOR_RUNNERS=1
