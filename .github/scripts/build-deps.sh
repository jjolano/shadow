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

HOOKKIT=9ed289b3c49e74035aa8aa847ad7e8e698a1b205
ALTLIST=9db09f92eff0404ae7fa9c2fe6c25ba13d5e02d7
LIBSANDY=9c77311172485e92bf0c439391be5a9565c877e4

case "$FLAVOR" in
    rootful-legacy)
        ARCHS='armv7 armv7s arm64 arm64e'
        TARGET=iphone:clang:13.7
        FLOOR=9.0
        SCHEME=
        ;;
    rootful-modern)
        ARCHS='arm64 arm64e'
        TARGET=iphone:clang:latest:14.0
        FLOOR=14.0
        SCHEME=
        ;;
    rootless)
        ARCHS='arm64 arm64e'
        TARGET=iphone:clang:latest:15.0
        FLOOR=15.0
        SCHEME=rootless
        ;;
    roothide)
        ARCHS='arm64 arm64e'
        TARGET=iphone:clang:latest:15.0
        FLOOR=15.0
        SCHEME=roothide
        ;;
    *) echo "unknown flavor: $FLAVOR" >&2; exit 2 ;;
esac

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
    git -C "$RUN/$3" checkout --quiet --detach "$2"
}

package_path() { # source directory
    local package
    package=$(<"$1/.theos/last_package")
    case "$package" in
        /*) printf '%s\n' "$package" ;;
        *) printf '%s/%s\n' "$1" "$package" ;;
    esac
}

stage_package() { # hookkit|altlist|sandy deb
    local dep=$1 deb=$2 extract source destination
    extract=$(mktemp -d "$RUN/extract.XXXXXX")
    dpkg-deb -x "$deb" "$extract"

    case "$dep" in
        hookkit)
            source=$(find "$extract" -type d -path '*/Library/Frameworks/HookKit.framework' -print -quit)
            destination="$PB/hookkit/$FLAVOR/HookKit.framework"
            ;;
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
        sed "/^Architecture:/a Depends: firmware (>= $floor)" "$source" > "$output"
    fi
}

common_make_args() {
    MAKE_ARGS=(
        "ARCHS=$ARCHS"
        "TARGET=$TARGET"
        "THEOS_LIBRARY_PATH=$RUN/theos-lib"
        "ADDITIONAL_CFLAGS=-fmodules-cache-path=$RUN/module-cache"
        "ADDITIONAL_OBJCFLAGS=-fmodules-cache-path=$RUN/module-cache"
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

    local xpc=${XPC_HEADERS:-$THEOS/sdks/iPhoneOS14.5.sdk/usr/include/xpc}
    [ -d "$xpc" ] || { echo "set XPC_HEADERS to an xpc headers directory" >&2; exit 1; }
    mkdir -p "$RUN/include"
    cp -R "$xpc" "$RUN/include/"

    MAKE_ARGS+=(
        "SDKBINPATH=$toolchain/bin"
        "THEOS_SDKS_PATH=$sdks"
        'TARGET_OS_DEPLOYMENT_VERSION=9.0'
        'TARGET_OS_DEPLOYMENT_VERSION_arm64e=12.0'
        "ADDITIONAL_CFLAGS=-I$RUN/include -fmodules-cache-path=$RUN/module-cache"
        "ADDITIONAL_OBJCFLAGS=-I$RUN/include -fmodules-cache-path=$RUN/module-cache -Wno-unguarded-availability-new"
    )
}

build_hookkit() {
    if [ "$FLAVOR" = rootful-legacy ]; then
        if [ -n "${HOOKKIT_LEGACY_DEB:-}" ]; then
            [ -f "$HOOKKIT_LEGACY_DEB" ] || { echo "HOOKKIT_LEGACY_DEB does not exist" >&2; exit 1; }
            stage_package hookkit "$HOOKKIT_LEGACY_DEB"
            return
        fi

        clone_pin jjolano/HookKit "$HOOKKIT" hookkit
        local source=$RUN/hookkit deb
        git -C "$source" apply "$ROOT/.github/patches/hookkit-legacy.patch"
        (cd "$source" && make clean && make package FINALPACKAGE=1 HOOKKIT_LEGACY=1 \
            "${MAKE_ARGS[@]}" "_THEOS_DEB_PACKAGE_CONTROL_PATH=$ROOT/.github/controls/hookkit-legacy")
        deb=$(package_path "$source")
        stage_package hookkit "$deb"
        return
    fi

    clone_pin jjolano/HookKit "$HOOKKIT" hookkit
    local source=$RUN/hookkit control=$RUN/hookkit.control deb
    write_control_floor "$source/control" "$control" "$FLOOR"
    (cd "$source" && make clean && make package FINALPACKAGE=1 "${MAKE_ARGS[@]}" \
        "_THEOS_DEB_PACKAGE_CONTROL_PATH=$control")
    deb=$(package_path "$source")
    stage_package hookkit "$deb"
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
build_hookkit
build_altlist
build_sandy
echo "dependencies staged: $FLAVOR"
