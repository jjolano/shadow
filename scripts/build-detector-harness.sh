#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${THEOS:?THEOS must point to Theos}"

"$ROOT/scripts/fetch-detector-sdks.sh" iossecuritysuite
"$ROOT/scripts/fetch-detector-sdks.sh" dtt
"$ROOT/scripts/fetch-detector-sdks.sh" freerasp
"$ROOT/scripts/fetch-detector-sdks.sh" roothider
"$ROOT/scripts/fetch-detector-sdks.sh" bat
"$ROOT/scripts/fetch-detector-sdks.sh" safetynet
"$ROOT/scripts/fetch-detector-sdks.sh" devicesecuritykit
"$ROOT/scripts/fetch-detector-sdks.sh" jailmonkey
make -C "$ROOT/Shadow.framework" THEOS_PACKAGE_SCHEME=rootless TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache
make -C "$ROOT/DetectorRunners/IOSSecuritySuite" stage THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/DetectorRunners/DTTJailbreakDetection" stage THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/DetectorRunners/FreeRASP" stage THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/DetectorRunners/Roothider" stage THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/DetectorRunners/BATJailbreakGuard" stage THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/tools/dyldprobe" stage THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    THEOS_LIBRARY_PATH=/tmp/shadow-dyldprobe-lib \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache
make -C "$ROOT/ShadowHarness" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    THEOS_LIBRARY_PATH="$ROOT/Shadow.framework/.theos/obj/debug" INCLUDE_DETECTOR_RUNNERS=1
