#!/usr/bin/env bash
set -e

PWD=$(dirname -- "$0")
cd $PWD

# Local dev-only dependency variants (rootless/rooted/legacy flavors of
# HookKit, AltList and the libsandy link stub). On a fresh machine, build
# those repos first and populate ../prebuilt accordingly.
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
        rootless|rooted) archs="arm64 arm64e" ;;
        legacy) archs="armv7 armv7s" ;;
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
}

stage_deps() {
    local flavor=$1
    rm -rf vendor/HookKit.framework
    mkdir -p vendor/HookKit.framework
    cp -R $PB/hookkit/$flavor/HookKit.framework/* vendor/HookKit.framework/
    # The rootless/legacy prebuilt HookKit flavors ship binary-only; the
    # public headers are identical across flavors, so seed them from rooted.
    if [ ! -f vendor/HookKit.framework/Headers/HookKit.h ]; then
        cp -R $PB/hookkit/rooted/HookKit.framework/Headers vendor/HookKit.framework/
    fi
    mkdir -p $THEOS/lib
    rm -rf $THEOS/lib/AltList.framework
    cp -R $PB/altlist/$flavor/AltList.framework $THEOS/lib/
    cp $PB/sandy/$flavor/libsandy.dylib $THEOS/lib/
    # The rootless pass runs with THEOS_PACKAGE_SCHEME=rootless, which makes
    # theos search only $THEOS/lib/iphone/rootless; mirror AltList/libsandy there.
    if [ "$flavor" = "rootless" ]; then
        mkdir -p $THEOS/lib/iphone/rootless
        rm -rf $THEOS/lib/iphone/rootless/AltList.framework
        cp -R $PB/altlist/rootless/AltList.framework $THEOS/lib/iphone/rootless/
        cp $PB/sandy/rootless/libsandy.dylib $THEOS/lib/iphone/rootless/
    fi
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

# build main project (rooted ver., iOS 12+; theos bumps the arm64e slice minos to 14.0)
build_rooted() {
    stage_deps rooted
    check_deps rooted
    make clean &&
    ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0 make package FINALPACKAGE=1 &&
    cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

    rm -rf $THEOS/lib/Shadow.framework
}

# build legacy ver. (armv7/armv7s, iOS 9+; 32-bit deps staged separately)
build_legacy() {
    stage_deps legacy
    check_deps legacy
    # PID-unique backup: the legacy pass mutates control in place; a fixed
    # /tmp path collides when two builds run in parallel (CI + local, or two
    # sessions). Restore on exit so a failed pass never leaves control dirty.
    local BAK=/tmp/shadow-control.bak.$$
    trap "mv $BAK control 2>/dev/null || true" EXIT
    cp control "$BAK"
    sed 's/firmware (>= 12.0)/firmware (>= 9.0)/' control > control.tmp && mv control.tmp control

    make clean &&
    ARCHS="armv7 armv7s" TARGET=iphone:clang:latest:9.0 make package FINALPACKAGE=1 &&
    cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/me.jjolano.shadow_4.0.0_iphoneos-arm-legacy.deb

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
    make -C Shadow.dylib ARCHS="arm64 arm64e"
}

case ${1:-all} in
    rootless) build_rootless ;;
    rooted) build_rooted ;;
    legacy) build_legacy ;;
    quick) build_quick ;;
    deps) check_deps "${2:-rooted}" ;;
    all) build_rootless; build_rooted; build_legacy ;;
    *) echo "usage: $0 [all|rootless|rooted|legacy|quick|deps <flavor>]" >&2; exit 1 ;;
esac
