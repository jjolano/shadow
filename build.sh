#!/usr/bin/env bash
set -e

cd -- "$(dirname -- "$0")"

# create fresh build directory
rm -rf build
mkdir -p build

# build main project (rootless ver., iOS 12+)
build_rootless() {
    make clean &&
    THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0 make package FINALPACKAGE=1 &&
    # theos records the deb it just built here; the name derives from control,
    # so version and arch never have to be repeated in this script
    cp -p "$(cat .theos/last_package)" build/

    rm -rf "${THEOS:?}/lib/HookKit.framework"
}

# build main project (rooted ver., iOS 12+; theos bumps the arm64e slice minos to 14.0)
build_rooted() {
    make clean &&
    ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0 make package FINALPACKAGE=1 &&
    cp -p "$(cat .theos/last_package)" build/

    rm -rf "${THEOS:?}/lib/HookKit.framework"
}

# build legacy ver. (armv7/armv7s, iOS 9+)
build_legacy() {
    # PID-unique backup: the legacy pass mutates control in place; a fixed
    # /tmp path collides when two builds run in parallel (CI + local, or two
    # sessions). Restore on exit so a failed pass never leaves control dirty.
    local BAK=/tmp/hookkit-control.bak.$$
    trap "mv '$BAK' control 2>/dev/null || true" EXIT
    cp control "$BAK"

    # Legacy ships under its own package id, mirroring me.jjolano.shadow.legacy.
    # Reusing me.jjolano.fmwk.hookkit would put two debs in the repo with an
    # identical Package/Version/Architecture triple, which APT cannot tell
    # apart -- it would serve whichever stanza it read last. The firmware
    # bounds are also made disjoint from the modern package's >= 12.0, so the
    # two can never both be candidates on one device.
    sed -e 's/^Package: \(.*\)$/Package: \1.legacy/' \
        -e 's/^Name: \(.*\)$/Name: \1 (legacy)/' \
        -e 's/firmware (>= 12.0)/firmware (>= 9.0), firmware (<< 12.0)/' \
        -e 's/^Conflicts: .*$/Conflicts: me.jjolano.fmwk.hookkit/' \
        -e 's/^Description: \(.*\)$/Description: \1 Legacy armv7\/armv7s build for iOS 9 - 11. No support will be given for this package./' \
        control > control.tmp &&
    printf 'Replaces: me.jjolano.fmwk.hookkit\nProvides: me.jjolano.fmwk.hookkit\n' >> control.tmp &&
    mv control.tmp control

    make clean &&
    ARCHS="armv7 armv7s" TARGET=iphone:clang:latest:9.0 make package FINALPACKAGE=1 &&
    cp -p "$(cat .theos/last_package)" build/

    rm -rf "${THEOS:?}/lib/HookKit.framework"
}

case ${1:-all} in
    rootless) build_rootless ;;
    rooted) build_rooted ;;
    legacy) build_legacy ;;
    all) build_rootless; build_rooted; build_legacy ;;
    *) echo "usage: $0 [all|rootless|rooted|legacy]" >&2; exit 1 ;;
esac
