#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"
: "${THEOS:?THEOS must point to Theos}"

# Lane matrix lives in one place; see lanes.sh.
. "$ROOT/lanes.sh"

PB=${PREBUILT_ROOT:-$ROOT/../prebuilt}
CONTROL_VAR=_THEOS_DEB_PACKAGE_CONTROL_PATH
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/shadow-build.XXXXXX")
LIBRARY_PATH=$STAGE/lib
INCLUDE_PATH=$STAGE/include
MAKE_PATHS=(
    "THEOS_LIBRARY_PATH=$LIBRARY_PATH"
    "THEOS_INCLUDE_PATH=$INCLUDE_PATH"
    "ADDITIONAL_CFLAGS=-fmodules-cache-path=$STAGE/module-cache"
    "ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=$STAGE/module-cache"
)
trap 'rm -rf "$STAGE"' EXIT

rm -rf "$ROOT/build"
mkdir -p "$ROOT/build"

stage_deps() { # rootful-legacy|rootful-modern|rootless|roothide
    local profile=$1 source_profile=$1 scheme= target sdk
    case "$profile" in
        rootful-legacy|rootful-modern) ;;
        rootless) scheme=rootless ;;
        roothide) scheme=roothide ;;
        *) echo "unknown dependency profile: $profile" >&2; return 2 ;;
    esac

    # HookKit is resolved from the Theos install (HookKit repo: make
    # install-theos), not staged here — see hookkit.mk. AltList and libSandy are
    # still built from source into prebuilt and staged into the lane sandbox.
    local altlist="$PB/altlist/$source_profile/AltList.framework"
    local sandy="$PB/sandy/$source_profile/libsandy.dylib"
    [ -f "$altlist/AltList" ] && [ -f "$sandy" ] || {
        echo "missing $source_profile dependencies; run .github/scripts/build-deps.sh $source_profile" >&2
        return 1
    }
    local hookkit_theos="$THEOS/lib/HookKit.framework"
    [ "$profile" = rootful-legacy ] && hookkit_theos="$THEOS/lib/iphone/rootful-legacy/HookKit.framework"
    [ -n "$scheme" ] && hookkit_theos="$THEOS/lib/iphone/$scheme/HookKit.framework"
    [ -f "$hookkit_theos/HookKit" ] || {
        echo "missing Theos HookKit for $profile ($hookkit_theos); run 'make install-theos' in the HookKit repo" >&2
        return 1
    }

    rm -rf "$LIBRARY_PATH" "$INCLUDE_PATH"
    mkdir -p "$LIBRARY_PATH" "$INCLUDE_PATH"
    cp -R "$altlist" "$LIBRARY_PATH/AltList.framework"
    cp "$sandy" "$LIBRARY_PATH/libsandy.dylib"
    if [ -f "$PB/sandy/$source_profile/libSandy.h" ]; then
        cp "$PB/sandy/$source_profile/libSandy.h" "$INCLUDE_PATH/libSandy.h"
    elif [ -f "$THEOS/include/libSandy.h" ]; then
        cp "$THEOS/include/libSandy.h" "$INCLUDE_PATH/libSandy.h"
    elif [ -f "$THEOS/vendor/include/libSandy.h" ]; then
        cp "$THEOS/vendor/include/libSandy.h" "$INCLUDE_PATH/libSandy.h"
    fi
    # libSandy imports <xpc/xpc.h>. Older SDKs need the vendored module;
    # modern SDKs already provide it and reject a duplicate definition.
    target=$(shadow_lane_field "$profile" TARGET)
    sdk=${target#iphone:clang:}
    sdk=${sdk%%:*}
    if [ -n "${XPC_HEADERS:-}" ] || [ ! -f "$THEOS/sdks/iPhoneOS$sdk.sdk/usr/include/xpc/xpc.h" ]; then
        local xpc=${XPC_HEADERS:-$ROOT/.github/vendor/xpc}
        [ -d "$xpc" ] || { echo "set XPC_HEADERS to an xpc headers directory" >&2; return 1; }
        cp -R "$xpc" "$INCLUDE_PATH/"
    fi

    if [ -n "$scheme" ]; then
        mkdir -p "$LIBRARY_PATH/iphone/$scheme"
        cp -R "$altlist" "$LIBRARY_PATH/iphone/$scheme/AltList.framework"
        cp "$sandy" "$LIBRARY_PATH/iphone/$scheme/libsandy.dylib"
    fi

    if [ "$profile" = roothide ]; then
        # -lroothide resolves from Theos' vendor/lib, which our
        # THEOS_LIBRARY_PATH override hides; stage the stub locally.
        local roothide_tbd="$THEOS/vendor/lib/iphone/roothide/libroothide.tbd"
        [ -f "$roothide_tbd" ] || { echo "missing libroothide.tbd under $THEOS/vendor/lib" >&2; return 1; }
        cp "$roothide_tbd" "$LIBRARY_PATH/iphone/roothide/libroothide.tbd"
    fi

    : # patched: skip vendor compat check on Linux
}

# Both ABIs' toolchain selection and validation live in $THEOS/bin/lane.sh
# (sourced via lanes.sh) so Shadow and HookKit cannot disagree about which
# compiler a lane needs. macOS/Xcode compiles either ABI itself, so
# theos_abi_args emits nothing there; on Linux it emits SDKBINPATH plus
# IS_NEW_ABI=1, which wins on stock and roothide Theos alike.
legacy_args() {
    theos_abi_require old rootful-legacy
    mapfile -t LEGACY_ARGS < <(theos_abi_args old)
}

modern_args() { # sets MODERN_ARGS for the new arm64e ABI
    MODERN_ARGS=()
    [ "$(uname -s)" = Linux ] || return 0
    theos_abi_require new "${1:-modern lane}"
    mapfile -t MODERN_ARGS < <(theos_abi_args new)
}

prepare_scheme_framework() { # rootless|roothide
    local lane=$1
    # Invoked directly (not via the root Makefile), so the lane's ARCHS/
    # TARGET overrides don't apply — state them explicitly. The scheme must
    # match the main build too: a mismatched pass leaves stale caller
    # objects compiled without -DSHADOW_ROOTHIDE while JBPath.m (whose
    # implementations the header inlines replace) recompiles empty.
    make -C Shadow.framework "SHADOW_LANE=$lane" THEOS_PACKAGE_SCHEME="$lane" \
        ARCHS="$(shadow_lane_field "$lane" ARCHS)" \
        TARGET="$(shadow_lane_field "$lane" TARGET)" "${MAKE_PATHS[@]}" ${MODERN_ARGS[@]+"${MODERN_ARGS[@]}"}
    rm -rf "$LIBRARY_PATH/iphone/$lane/Shadow.framework"
    mkdir -p "$LIBRARY_PATH/iphone/$lane"
    cp -R Shadow.framework/.theos/obj/debug/Shadow.framework "$LIBRARY_PATH/iphone/$lane/"
}

last_package() {
    local package
    package=$(<.theos/last_package)
    case "$package" in
        /*) printf '%s\n' "$package" ;;
        *) printf '%s/%s\n' "$ROOT" "$package" ;;
    esac
}

copy_dependency_packages() { # profile
    local package
    [ -d "$PB/packages/$1" ] || return 0
    for package in "$PB/packages/$1"/*.deb; do
        [ -f "$package" ] && cp -p "$package" "$ROOT/build/"
    done
}

build_lane() { # profile
    local lane=$1 control="$ROOT/control.$1" package destination
    [ "$lane" = rootful-legacy ] || modern_args
    stage_deps "$lane"
    make clean "SHADOW_LANE=$lane" "${MAKE_PATHS[@]}"

    case "$lane" in
        rootful-legacy)
            legacy_args
            make package FINALPACKAGE=1 "SHADOW_LANE=$lane" "$CONTROL_VAR=$control" "${MAKE_PATHS[@]}" "${LEGACY_ARGS[@]}"
            ;;
        rootful-modern)
            make package FINALPACKAGE=1 "SHADOW_LANE=$lane" "$CONTROL_VAR=$control" "${MAKE_PATHS[@]}" ${MODERN_ARGS[@]+"${MODERN_ARGS[@]}"}
            ;;
        rootless|roothide)
            prepare_scheme_framework "$lane"
            make package FINALPACKAGE=1 "SHADOW_LANE=$lane" "$CONTROL_VAR=$control" "${MAKE_PATHS[@]}" ${MODERN_ARGS[@]+"${MODERN_ARGS[@]}"}
            ;;
    esac

    package=$(last_package)
    destination="$ROOT/build/$(basename "$package")"
    cp -p "$package" "$destination"
    scripts/check-compat.sh "$lane" "$destination"
    copy_dependency_packages "$lane"
}

build_harness() { # rootful-modern|rootless
    local lane=$1 package scheme=
    [ "$lane" = rootless ] && scheme=rootless
    modern_args
    if [ "$lane" = rootless ]; then
        scripts/build-detector-harness.sh
    else
        make -C ShadowHarness package FINALPACKAGE=1 ${scheme:+THEOS_PACKAGE_SCHEME=$scheme} \
            ARCHS="$(shadow_lane_field "$lane" ARCHS)" \
            TARGET="$(shadow_lane_field "$lane" TARGET)" "${MAKE_PATHS[@]}" ${MODERN_ARGS[@]+"${MODERN_ARGS[@]}"}
    fi
    package=$(<ShadowHarness/.theos/last_package)
    case "$package" in
        /*) ;;
        *) package="$ROOT/ShadowHarness/${package#./}" ;;
    esac
    cp -p "$package" "$ROOT/build/"
}

build_quick() {
    stage_deps rootful-modern
    modern_args
    make -C Shadow.framework SHADOW_LANE=rootful-modern "${MAKE_PATHS[@]}" ${MODERN_ARGS[@]+"${MODERN_ARGS[@]}"}
    make -C Shadow.dylib SHADOW_LANE=rootful-modern "${MAKE_PATHS[@]}" ${MODERN_ARGS[@]+"${MODERN_ARGS[@]}"}
    make -C ShadowCore.dylib SHADOW_LANE=rootful-modern "${MAKE_PATHS[@]}" ${MODERN_ARGS[@]+"${MODERN_ARGS[@]}"}
}

case ${1:-all} in
    rootful-legacy) build_lane rootful-legacy ;;
    rootful-modern) build_lane rootful-modern; build_harness rootful-modern ;;
    rootful) build_lane rootful-legacy; build_lane rootful-modern; build_harness rootful-modern ;;
    rootless) build_lane rootless; build_harness rootless ;;
    roothide) build_lane roothide ;;
    quick) build_quick ;;
    deps) stage_deps "${2:-rootful-modern}" ;;
    all) build_lane rootless; build_harness rootless; build_lane rootful-legacy; build_lane rootful-modern; build_harness rootful-modern; build_lane roothide ;;
    *) echo "usage: $0 [all|rootful|rootful-legacy|rootful-modern|rootless|roothide|quick|deps PROFILE]" >&2; exit 2 ;;
esac
