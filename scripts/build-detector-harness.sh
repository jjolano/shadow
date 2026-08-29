#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${THEOS:?THEOS must point to Theos}"
ABI_ARGS=()
if [ "$(uname -s)" = Linux ]; then
    tc=${NEWABI_TOOLCHAIN:-$THEOS/toolchain/modern/linux/iphone}
    [ -x "$tc/bin/clang" ] || { echo "missing new-ABI toolchain: $tc" >&2; exit 1; }
    ABI_ARGS=("SDKBINPATH=$tc/bin" "IS_NEW_ABI=1")
fi
m() { make "$@" ${ABI_ARGS[@]+"${ABI_ARGS[@]}"}; }
for id in iossecuritysuite jailbreakdetector securitytoolkit dtt freerasp devicesecuritykit; do
    "$ROOT/scripts/fetch-detector-sdks.sh" "$id"
done
m -C "$ROOT/Shadow.framework" THEOS_PACKAGE_SCHEME=rootless TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-detector-framework-module-cache
m -C "$ROOT/tools/dyldprobe" stage THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    THEOS_LIBRARY_PATH=/tmp/shadow-dyldprobe-lib \
    ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache \
    ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=/tmp/shadow-dyldprobe-module-cache
m -C "$ROOT/ShadowHarness" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless \
    TARGET=iphone:clang:16.5:15.0 ARCHS="arm64 arm64e" \
    THEOS_LIBRARY_PATH="$ROOT/Shadow.framework/.theos/obj/debug"
