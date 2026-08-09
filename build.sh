#!/usr/bin/env bash
set -e

PWD=$(dirname -- "$0")
cd $PWD

# Local dev-only dependency variants (rootless/rooted/legacy flavors of
# HookKit, AltList and the libsandy link stub). On a fresh machine, build
# those repos first and populate ../prebuilt accordingly. The fat flavor
# lipos the rooted (arm64/arm64e) and legacy (armv7/armv7s) slices into
# one 4-arch dep set (see stage_deps).
PB=../prebuilt

# Dep slice validation. stage_deps overwrites the shared dep locations, so a
# concurrent or stale staging leaves wrong slices behind and `make` fails at
# link time with confusing "missing required architecture" errors. check_deps
# verifies the slices the flavor needs and re-stages once on mismatch, then
# fails fast with a clear message instead of a linker error.
LIPO=${LIPO:-$THEOS/toolchain/linux/iphone/bin/lipo}

has_slices() { # file arch...
    local f=$1
    shift
    [ -f "$f" ] || return 1
    local info
    info=$("$LIPO" -info "$f" 2>/dev/null) || return 1
    local archs
    archs=$(echo "$info" | tr ':' ' ')
    local a
    for a in "$@"; do
        echo "$archs" | grep -qw "$a" || return 1
    done
    return 0
}

check_deps() { # flavor
    local flavor=$1
    local archs
    case $flavor in
        rootless|rooted|roothide) archs="arm64 arm64e" ;;
        fat) archs="armv7 armv7s arm64 arm64e" ;;
        *) echo "check_deps: unknown flavor $flavor" >&2; return 1 ;;
    esac

    local deps=(vendor/HookKit.framework/HookKit "$THEOS/lib/libsandy.dylib" "$THEOS/lib/AltList.framework/AltList")
    local bad=0
    local dep
    for dep in "${deps[@]}"; do
        if ! has_slices "$dep" $archs; then
            echo "deps: $dep missing [$archs] — re-staging $flavor deps" >&2
            bad=1
        fi
    done

    if [ $bad -eq 1 ]; then
        stage_deps "$flavor"
    fi

    # Fail fast if staging couldn't fix it (missing ../prebuilt flavor).
    for dep in "${deps[@]}"; do
        if ! has_slices "$dep" $archs; then
            echo "deps: $dep still wrong after staging ($flavor) — check ../prebuilt" >&2
            exit 1
        fi
    done

    # RootBridge lives in vendor/ (built by build-deps.sh), not ../prebuilt.
    if [ "$flavor" = "fat" ] && ! has_slices vendor/RootBridge.framework/RootBridge $archs; then
        echo "deps: vendor/RootBridge.framework missing [$archs] — run build-deps.sh fat" >&2
        exit 1
    fi
}

stage_deps() {
    local flavor=$1
    # lipo the disjoint rooted (arm64/arm64e) + legacy (armv7/armv7s)
    # prebuilt slices into one 4-arch fat file.
    lipo_fat() { "$LIPO" -create "$1" "$2" -output "$3"; }
    case $flavor in
        fat)
            # Rooted flavor ships the public headers; legacy is binary-only.
            rm -rf vendor/HookKit.framework
            mkdir -p vendor/HookKit.framework
            cp -R $PB/hookkit/rooted/HookKit.framework/* vendor/HookKit.framework/
            lipo_fat $PB/hookkit/rooted/HookKit.framework/HookKit $PB/hookkit/legacy/HookKit.framework/HookKit vendor/HookKit.framework/HookKit
            mkdir -p $THEOS/lib
            rm -rf $THEOS/lib/AltList.framework
            cp -R $PB/altlist/rooted/AltList.framework $THEOS/lib/
            lipo_fat $PB/altlist/rooted/AltList.framework/AltList $PB/altlist/legacy/AltList.framework/AltList $THEOS/lib/AltList.framework/AltList
            lipo_fat $PB/sandy/rooted/libsandy.dylib $PB/sandy/legacy/libsandy.dylib $THEOS/lib/libsandy.dylib
            # Framework link order resolves $THEOS/lib before -F../vendor, so
            # the 4-slice merge must also land there (per-flavor passes got
            # this from build-deps installing the matching variant; the fat
            # pass leaves the legacy one behind). HookKit/RootBridge merge
            # lives in vendor/; AltList/libsandy are already fat above.
            for fw in HookKit RootBridge; do
                rm -rf $THEOS/lib/$fw.framework
                cp -R vendor/$fw.framework $THEOS/lib/
            done
            ;;
        rootless|rooted|roothide)
            rm -rf vendor/HookKit.framework
            mkdir -p vendor/HookKit.framework
            cp -R $PB/hookkit/$flavor/HookKit.framework/* vendor/HookKit.framework/
            # The rootless prebuilt HookKit flavor ships binary-only; the
            # public headers are identical across flavors, so seed them from rooted.
            if [ ! -f vendor/HookKit.framework/Headers/HookKit.h ]; then
                cp -R $PB/hookkit/rooted/HookKit.framework/Headers vendor/HookKit.framework/
            fi
            mkdir -p $THEOS/lib
            rm -rf $THEOS/lib/AltList.framework
            cp -R $PB/altlist/$flavor/AltList.framework $THEOS/lib/
            cp $PB/sandy/$flavor/libsandy.dylib $THEOS/lib/
            # The rootless/roothide schemes run with their own
            # THEOS_PACKAGE_SCHEME, which makes theos search only
            # $THEOS/lib/iphone/<scheme>; mirror AltList/libsandy there.
            if [ "$flavor" = "rootless" ]; then
                mkdir -p $THEOS/lib/iphone/rootless
                rm -rf $THEOS/lib/iphone/rootless/AltList.framework
                cp -R $PB/altlist/rootless/AltList.framework $THEOS/lib/iphone/rootless/
                cp $PB/sandy/rootless/libsandy.dylib $THEOS/lib/iphone/rootless/
            elif [ "$flavor" = "roothide" ]; then
                mkdir -p $THEOS/lib/iphone/roothide
                rm -rf $THEOS/lib/iphone/roothide/AltList.framework
                cp -R $PB/altlist/rootless/AltList.framework $THEOS/lib/iphone/roothide/
                cp $PB/sandy/rootless/libsandy.dylib $THEOS/lib/iphone/roothide/
            fi
            ;;
        *) echo "stage_deps: unknown flavor $flavor" >&2; return 1 ;;
    esac
}

# create fresh build directory
rm -rf $PWD/build
mkdir -p $PWD/build

# build main project (rootless ver., iOS 15+)
build_rootless() {
    stage_deps rootless
    check_deps rootless
    make clean &&
    # The rootless scheme never installs Shadow.framework into $THEOS/lib/iphone/rootless
    # on this theos (rooted scheme installs to $THEOS/lib fine), so build the framework
    # first and stage it explicitly — otherwise the tweak links against a stale copy.
    THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0 make -C Shadow.framework &&
    rm -rf $THEOS/lib/iphone/rootless/Shadow.framework &&
    cp -R Shadow.framework/.theos/obj/debug/Shadow.framework $THEOS/lib/iphone/rootless/ &&
    THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0 make package FINALPACKAGE=1 &&
    cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

    rm -rf $THEOS/lib/Shadow.framework
}

# build fat ver. — one package, armv7/armv7s + arm64/arm64e, iOS 9+.
# Replaces the old rooted + legacy debs: 32-bit devices get dylib-only
# (postinst strips the arm64-only shadowd + its plist there), and on
# 64-bit iOS < 12 the rooted dep slices (minos 12.0) can't load, so
# postinst strips injection too — see layout/DEBIAN/postinst.
build_fat() {
    stage_deps fat
    check_deps fat
    # PID-unique backup: the fat pass mutates control in place; a fixed
    # /tmp path collides when two builds run in parallel (CI + local, or two
    # sessions). Restore on exit so a failed pass never leaves control dirty.
    local BAK=/tmp/shadow-control.bak.$$
    trap "mv $BAK control 2>/dev/null || true" EXIT
    cp control "$BAK"
    sed 's/firmware (>= 12.0)/firmware (>= 9.0)/' control > control.tmp && mv control.tmp control

    make clean &&
    ARCHS="armv7 armv7s arm64 arm64e" TARGET=iphone:clang:latest:9.0 make package FINALPACKAGE=1 &&
    cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/me.jjolano.shadow_4.0.0_iphoneos-arm.deb

    rm -rf $THEOS/lib/Shadow.framework
}

# Fast iteration for agent/subagent work: no packaging, no clean — compile
# framework + dylib only, with rooted deps verified. The full aggregate
# `make` from the repo root is the final gate before packaging.
build_quick() {
    check_deps rooted
    # Pin ARCHS: the subproject Makefiles don't declare it, so a bare
    # `make -C` defaults to including armv7, which cannot link against the
    # rooted 2-slice deps. arm64/arm64e = the rooted flavor's slices.
    make -C Shadow.framework ARCHS="arm64 arm64e" &&
    make -C Shadow.dylib ARCHS="arm64 arm64e" &&
    make -C ShadowCore.dylib ARCHS="arm64 arm64e"
}

# roothide flavor — iOS 15-17, random-named jbroot (no /var/jb). Requires the
# roothide theos fork (THEOS_PACKAGE_SCHEME=roothide) and libroothide; the
# Makefiles drop RootBridge and define SHADOW_ROOTHIDE for this scheme.
build_roothide() {
    stage_deps roothide
    check_deps roothide
    # Same PID-unique control mutation pattern as the fat pass: the roothide
    # flavor must not depend on RootBridge (the seam links libroothide instead).
    local BAK=/tmp/shadow-control-roothide.bak.$$
    trap "mv $BAK control 2>/dev/null || true" EXIT
    cp control "$BAK"
    # roothide bootstrap: iOS 15.0-17.0 only; drop RootBridge dep (seam uses
    # libroothide) and raise the firmware floor from the shared 12.0.
    sed -e 's/, me.jjolano.fmwk.rootbridge//' -e 's/firmware (>= 12.0)/firmware (>= 15.0)/' control > control.tmp && mv control.tmp control

    make clean &&
    THEOS_PACKAGE_SCHEME=roothide ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:17.0 make -C Shadow.framework &&
    rm -rf $THEOS/lib/iphone/roothide/Shadow.framework &&
    cp -R Shadow.framework/.theos/obj/debug/Shadow.framework $THEOS/lib/iphone/roothide/ &&
    THEOS_PACKAGE_SCHEME=roothide ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:17.0 make package FINALPACKAGE=1 &&
    cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

    rm -rf $THEOS/lib/Shadow.framework
}

case ${1:-all} in
    rootless) build_rootless ;;
    fat) build_fat ;;
    roothide) build_roothide ;;
    quick) build_quick ;;
    deps) check_deps "${2:-rooted}" ;;
    all) build_rootless; build_fat ;;
    *) echo "usage: $0 [all|rootless|fat|roothide|quick|deps <flavor>]" >&2; exit 1 ;;
esac
