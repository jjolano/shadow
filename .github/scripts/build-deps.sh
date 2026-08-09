#!/usr/bin/env bash
# Build the prebuilt dependency variants (HookKit/AltList/libsandy) from pinned
# upstream commits into ../prebuilt — the layout build.sh expects. Run from the
# repo root: bash .github/scripts/build-deps.sh <rootless|rooted|legacy|fat>
#
# The pinned commits must match what the packaged debs (control Depends) ship;
# bump deliberately. HookKit is jjolano's own fork (Substrate/Substitute
# backends); AltList/libsandy are opa334's, pinned at upstream HEAD.
# fat = rooted (arm64/arm64e) + legacy (armv7/armv7s) builds lipo-merged
# into one 4-arch flavor (also merges vendor/RootBridge.framework).
set -euo pipefail

FLAVOR=${1:?usage: build-deps.sh <rootless|rooted|legacy|fat>}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export THEOS=${THEOS:-/opt/theos}
PB=$ROOT/../prebuilt
WORK=${WORK:-/tmp/shadow-deps}
LIPO=${LIPO:-$THEOS/toolchain/linux/iphone/bin/lipo}

HOOKKIT=77324f7ad01c7f6294fe4a9ecf809e9396638cb2
ALTLIST=9db09f92eff0404ae7fa9c2fe6c25ba13d5e02d7
LIBSANDY=9c77311172485e92bf0c439391be5a9565c877e4
ROOTBRIDGE=2ba635ce088c0c3ded517b07b741c7351d20239e

clone_pin() { # <repo> <sha> <dir>
    if [[ ! -d "$WORK/$3/.git" ]]; then
        git clone --quiet "https://github.com/$1" "$WORK/$3"
    fi
    git -C "$WORK/$3" fetch --quiet --depth 1 origin "$2"
    git -C "$WORK/$3" checkout --quiet --detach FETCH_HEAD
}

build_variant() { # <rootless|rooted|legacy>
    local FLAVOR=$1

    mkdir -p "$PB/hookkit/$FLAVOR" "$PB/altlist/$FLAVOR" "$PB/sandy/$FLAVOR"

    case "$FLAVOR" in
        rootless) SCHEME=THEOS_PACKAGE_SCHEME=rootless; ARCHS="arm64 arm64e"; HK_TARGET= ;;
        rooted)   SCHEME=; ARCHS="arm64 arm64e"; HK_TARGET= ;;
        # HookKit's Makefile pins deployment 12.0, which clang rejects for 32-bit
        # targets (max iOS 10); lower the floor for the armv7 pass only.
        legacy)   SCHEME=; ARCHS="armv7 armv7s"; HK_TARGET=TARGET=iphone:clang:latest:9.0 ;;
        *) echo "unknown flavor: $FLAVOR" >&2; exit 1 ;;
    esac

    # Rootless scheme installs into $THEOS/lib/iphone/rootless, others into $THEOS/lib
    if [ "$FLAVOR" = rootless ]; then
        LIBDIR=$THEOS/lib/iphone/rootless
    else
        LIBDIR=$THEOS/lib
    fi

    # --- RootBridge (jjolano; built FIRST — HookKit links the installed framework
    # from $THEOS/lib, so it must be the per-flavor build, not a stale one) ---
    clone_pin jjolano/RootBridge "$ROOTBRIDGE" rootbridge
(
    cd "$WORK/rootbridge"
    make clean >/dev/null 2>&1 || true
    env $SCHEME ARCHS="$ARCHS" make package FINALPACKAGE=1
    rm -rf "$ROOT/vendor/RootBridge.framework"
    cp -R "$LIBDIR/RootBridge.framework" "$ROOT/vendor/"
    # No RootBridge_PUBLIC_HEADERS in the Makefile; the framework install skips
    # Headers, which Shadow.framework needs (<RootBridge.h>).
    [[ -d "$ROOT/vendor/RootBridge.framework/Headers" ]] ||
        cp -R Headers "$ROOT/vendor/RootBridge.framework/"
)

# --- HookKit (jjolano's fork; vendored fishhook/substrate/substitute backends) ---
clone_pin jjolano/HookKit "$HOOKKIT" hookkit
(
    cd "$WORK/hookkit"
    make clean >/dev/null 2>&1 || true
    env $SCHEME $HK_TARGET ARCHS="$ARCHS" make package FINALPACKAGE=1
    rm -rf "$PB/hookkit/$FLAVOR/HookKit.framework"
    cp -R "$LIBDIR/HookKit.framework" "$PB/hookkit/$FLAVOR/"
    # No HookKit_PUBLIC_HEADERS in the Makefile, so the framework install skips
    # Headers; seed them from the source tree (stage_deps expects them).
    [[ -d "$PB/hookkit/$FLAVOR/HookKit.framework/Headers" ]] ||
        cp -R Headers "$PB/hookkit/$FLAVOR/HookKit.framework/"
)

# --- AltList (opa334) ---
clone_pin opa334/AltList "$ALTLIST" altlist
(
    cd "$WORK/altlist"
    # after-AltList-stage symlinks into Library/PreferenceBundles, which theos
    # never creates for framework-only packages on Linux; pre-create it.
    grep -q before-AltList-stage Makefile ||
        printf 'before-AltList-stage::\n\t@mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceBundles\n' >> Makefile
    make clean >/dev/null 2>&1 || true
    env $SCHEME ARCHS="$ARCHS" make package FINALPACKAGE=1
    rm -rf "$PB/altlist/$FLAVOR/AltList.framework"
    cp -R "$LIBDIR/AltList.framework" "$PB/altlist/$FLAVOR/"
)

    # --- libsandy (opa334; library only — sandyd/SandyProxy subprojects skipped) ---
    clone_pin opa334/libSandy "$LIBSANDY" libsandy
    (
        cd "$WORK/libsandy"
        make clean >/dev/null 2>&1 || true
        env $SCHEME ARCHS="$ARCHS" ONLY_LIBRARY=1 make package FINALPACKAGE=1
        cp "$LIBDIR/libsandy.dylib" "$PB/sandy/$FLAVOR/libsandy.dylib"
        # Public header: theos does not install it with `make package`; the tweak
        # imports <libSandy.h>, which theos resolves from $THEOS/include.
        mkdir -p "$THEOS/include"
        cp libSandy.h "$THEOS/include/"
    )

    echo "deps staged: $FLAVOR"
}

merge_fat() { # lipo the rooted+legacy prebuilt flavors into .../fat/
    for dep in hookkit altlist; do
        rm -rf "$PB/$dep/fat"
        mkdir -p "$PB/$dep/fat"
        cp -R "$PB/$dep/rooted/." "$PB/$dep/fat/"
    done
    mkdir -p "$PB/sandy/fat"
    "$LIPO" -create "$PB/hookkit/rooted/HookKit.framework/HookKit" "$PB/hookkit/legacy/HookKit.framework/HookKit" \
        -output "$PB/hookkit/fat/HookKit.framework/HookKit"
    "$LIPO" -create "$PB/altlist/rooted/AltList.framework/AltList" "$PB/altlist/legacy/AltList.framework/AltList" \
        -output "$PB/altlist/fat/AltList.framework/AltList"
    "$LIPO" -create "$PB/sandy/rooted/libsandy.dylib" "$PB/sandy/legacy/libsandy.dylib" \
        -output "$PB/sandy/fat/libsandy.dylib"
}

case "$FLAVOR" in
    fat)
        # build_variant leaves its RootBridge build in vendor/; snapshot the
        # rooted one before the legacy pass overwrites vendor/, then lipo the
        # disjoint slice sets (rooted arm64/arm64e + legacy armv7/armv7s).
        build_variant rooted
        rm -rf "$WORK/rb-rooted"
        mv "$ROOT/vendor/RootBridge.framework" "$WORK/rb-rooted"
        build_variant legacy
        "$LIPO" -create "$WORK/rb-rooted/RootBridge" "$ROOT/vendor/RootBridge.framework/RootBridge" \
            -output "$WORK/rb-fat" &&
        mv "$WORK/rb-fat" "$ROOT/vendor/RootBridge.framework/RootBridge"
        rm -rf "$WORK/rb-rooted"
        merge_fat
        ;;
    *) build_variant "$FLAVOR" ;;
esac
