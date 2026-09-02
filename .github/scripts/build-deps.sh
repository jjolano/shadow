#!/usr/bin/env bash
# Build pinned dependency packages and stage their exact packaged binaries.
set -euo pipefail

FLAVOR=${1:?usage: build-deps.sh <rootful-legacy|rootful-modern|rootless|roothide>}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export THEOS=${THEOS:-/opt/theos}
PB=${PREBUILT_ROOT:-$ROOT/../prebuilt}
WORK_BASE=${WORK:-/tmp}
RUN=$(mktemp -d "$WORK_BASE/shadow-deps.XXXXXX")
trap 'rm -rf "$RUN"' EXIT

# Lane matrix lives in one place; see build-support/lanes.sh.
. "$ROOT/build-support/lanes.sh"

# HookKit is provisioned into Theos (see .github/scripts/install-hookkit-theos.sh
# and the HOOKKIT pin in build.yml), not built here.
ALTLIST=9db09f92eff0404ae7fa9c2fe6c25ba13d5e02d7
LIBSANDY=9c77311172485e92bf0c439391be5a9565c877e4

ARCHS=$(shadow_lane_field "$FLAVOR" ARCHS) || exit 2
TARGET=$(shadow_lane_field "$FLAVOR" TARGET) || exit 2
FLOOR=$(shadow_lane_field "$FLAVOR" FLOOR) || exit 2
SCHEME=$(shadow_lane_field "$FLAVOR" SCHEME) || exit 2

if [ "$FLAVOR" != rootful-legacy ]; then
    [ "$(uname -s)" = Darwin ] || {
        echo "$FLAVOR requires macOS/Xcode for the new arm64e ABI" >&2
        exit 1
    }
    xcode_major=$(xcodebuild -version | awk 'NR == 1 { split($2, v, "."); print v[1] }')
    [ "$xcode_major" -ge 12 ] || { echo "$FLAVOR requires Xcode 12 or newer" >&2; exit 1; }
fi

# One invocation produces one exact dependency set; do not publish stale debs
# left by an older version of the same flavor.
rm -rf "$PB/packages/$FLAVOR"
mkdir -p "$PB/packages/$FLAVOR"

clone_pin() { # repo sha directory
    local local_source=${DEPS_SOURCE_ROOT:-}/${1##*/}
    if [ -d "$local_source/.git" ]; then
        git clone --quiet "$local_source" "$RUN/$3"
    else
        git clone --quiet "https://github.com/$1" "$RUN/$3"
    fi
    # A pinned SHA may be unreachable from any ref (rewritten history);
    # clone only fetches refs, so fall back to fetching the commit itself.
    git -C "$RUN/$3" checkout --quiet --detach "$2" 2>/dev/null || {
        git -C "$RUN/$3" fetch --quiet origin "$2" &&
        git -C "$RUN/$3" checkout --quiet --detach FETCH_HEAD
    }
}

package_path() { # source directory
    local package
    package=$(<"$1/.theos/last_package")
    case "$package" in
        /*) printf '%s\n' "$package" ;;
        *) printf '%s/%s\n' "$1" "$package" ;;
    esac
}

stage_package() { # altlist|sandy deb
    local dep=$1 deb=$2 extract source destination
    extract=$(mktemp -d "$RUN/extract.XXXXXX")
    dpkg-deb -x "$deb" "$extract"

    case "$dep" in
        altlist)
            source=$(find "$extract" -type d -path '*/Library/Frameworks/AltList.framework' -print -quit)
            destination="$PB/altlist/$FLAVOR/AltList.framework"
            ;;
        sandy)
            source=$(find "$extract" -type f -path '*/usr/lib/libsandy.dylib' -print -quit)
            destination="$PB/sandy/$FLAVOR/libsandy.dylib"
            ;;
        *) echo "unknown dependency: $dep" >&2; return 2 ;;
    esac

    [ -n "$source" ] || { echo "$dep payload missing from $deb" >&2; return 1; }
    rm -rf "$destination"
    mkdir -p "$(dirname "$destination")"
    cp -R "$source" "$destination"
    mkdir -p "$PB/packages/$FLAVOR"
    cp -p "$deb" "$PB/packages/$FLAVOR/"
}

write_control_floor() { # source control, output, floor
    local source=$1 output=$2 floor=$3
    if grep -q '^Depends:.*firmware' "$source"; then
        sed -E "s/firmware \(>= [0-9.]+\)/firmware (>= $floor)/" "$source" > "$output"
    else
        # BSD sed's a-command needs a backslash-newline; awk is portable.
        awk -v depends="Depends: firmware (>= $floor)" \
            '!done && /^Architecture:/ { print; print depends; done = 1; next } \
             { print }' "$source" > "$output"
    fi
}

common_make_args() {
    # libSandy imports <xpc/xpc.h>; none of the SDKs used here ship xpc
    # headers (pinned old-ABI SDKs, staged 16.5 SDK). Stage the vendored
    # copy unless the caller points XPC_HEADERS elsewhere.
    local xpc=${XPC_HEADERS:-$ROOT/.github/vendor/xpc}
    [ -d "$xpc" ] || { echo "no xpc headers at $xpc (set XPC_HEADERS)" >&2; exit 1; }
    mkdir -p "$RUN/include"
    cp -R "$xpc" "$RUN/include/"

    MAKE_ARGS=(
        "ARCHS=$ARCHS"
        "TARGET=$TARGET"
        "THEOS_LIBRARY_PATH=$RUN/theos-lib"
        "ADDITIONAL_CFLAGS=-I$RUN/include -fmodules-cache-path=$RUN/module-cache"
        "ADDITIONAL_OBJCFLAGS=-I$RUN/include -fmodules-cache-path=$RUN/module-cache"
    )
    [ -z "$SCHEME" ] || MAKE_ARGS+=("THEOS_PACKAGE_SCHEME=$SCHEME")
}

legacy_make_args() {
    local toolchain=${OLDABI_TOOLCHAIN:-$THEOS/toolchain/oldabi/linux/iphone}
    local sdks=${OLDABI_SDKS:-$THEOS/sdks}
    [ -x "$toolchain/bin/clang" ] || { echo "missing old-ABI clang: $toolchain/bin/clang" >&2; exit 1; }
    [ -d "$sdks/iPhoneOS13.7.sdk" ] || { echo "missing iPhoneOS13.7.sdk under $sdks" >&2; exit 1; }
    local major
    major=$("$toolchain/bin/clang" -dumpversion)
    major=${major%%.*}
    [ "$major" -lt 12 ] || { echo "old-ABI lane requires Clang older than 12" >&2; exit 1; }
    export OLDABI_TOOLCHAIN=$toolchain OLDABI_SDKS=$sdks

    MAKE_ARGS+=(
        "SDKBINPATH=$toolchain/bin"
        "THEOS_SDKS_PATH=$sdks"
        "TARGET_OS_DEPLOYMENT_VERSION=$(shadow_lane_field "$FLAVOR" DEPLOY)"
        "TARGET_OS_DEPLOYMENT_VERSION_arm64e=$(shadow_lane_field "$FLAVOR" DEPLOY_ARM64E)"
        "ADDITIONAL_CFLAGS=-I$RUN/include -fmodules-cache-path=$RUN/module-cache"
        "ADDITIONAL_OBJCFLAGS=-I$RUN/include -fmodules-cache-path=$RUN/module-cache -Wno-unguarded-availability-new"
    )
}

build_altlist() {
    clone_pin opa334/AltList "$ALTLIST" altlist
    local source=$RUN/altlist control deb
    git -C "$source" apply "$ROOT/.github/patches/altlist-stage.patch"
    if [ "$FLAVOR" = rootful-legacy ]; then
        git -C "$source" apply "$ROOT/.github/patches/altlist-legacy.patch"
        control=$ROOT/.github/controls/altlist-legacy
    else
        control=$RUN/altlist.control
        write_control_floor "$source/control" "$control" "$FLOOR"
    fi
    (cd "$source" && make clean && make package FINALPACKAGE=1 "${MAKE_ARGS[@]}" \
        "_THEOS_DEB_PACKAGE_CONTROL_PATH=$control")
    deb=$(package_path "$source")
    stage_package altlist "$deb"
}

build_sandy() {
    clone_pin opa334/libSandy "$LIBSANDY" libsandy
    local source=$RUN/libsandy control deb
    if [ "$FLAVOR" = roothide ]; then
        git -C "$source" apply "$ROOT/.github/patches/libsandy-roothide.patch"
    fi
    if [ "$FLAVOR" = rootful-legacy ]; then
        control=$ROOT/.github/controls/libsandy-legacy
    else
        control=$RUN/libsandy.control
        write_control_floor "$source/control" "$control" "$FLOOR"
    fi
    (cd "$source" && make clean && make package FINALPACKAGE=1 ONLY_LIBRARY=1 \
        "${MAKE_ARGS[@]}" "_THEOS_DEB_PACKAGE_CONTROL_PATH=$control")
    deb=$(package_path "$source")
    stage_package sandy "$deb"
    cp "$source/libSandy.h" "$PB/sandy/$FLAVOR/libSandy.h"
}

common_make_args
[ "$FLAVOR" != rootful-legacy ] || legacy_make_args
# HookKit is provisioned into Theos (HookKit repo: make install-theos), not
# staged here; build.sh resolves it from $THEOS/lib per lane. build-deps only
# builds the from-source deps that are not published as a Theos install.
build_altlist
build_sandy
echo "dependencies staged: $FLAVOR"
