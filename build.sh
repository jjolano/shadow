#!/usr/bin/env bash
set -e

cd -- "$(dirname -- "$0")"

# create fresh build directory
rm -rf build
mkdir -p build

# Rooted: one fat package spanning armv7 through arm64e, matching how 1.0.x
# shipped. The Makefile defaults already cover this, so no overrides here.
# theos records the deb it just built in .theos/last_package and derives the
# name from control, so version and arch are never repeated in this script.
build_rooted() {
    make clean &&
    make package FINALPACKAGE=1 &&
    cp -p "$(cat .theos/last_package)" build/

    rm -rf "${THEOS:?}/lib/HookKit.framework"
}

# Rootless: modern jailbreaks only, so 64-bit slices and a 12.0 floor. The
# Architecture field (iphoneos-arm64) is what actually keeps this deb away
# from rooted devices, so control's shared 9.0 Depends floor is harmless here.
build_rootless() {
    make clean &&
    THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0 make package FINALPACKAGE=1 &&
    cp -p "$(cat .theos/last_package)" build/

    rm -rf "${THEOS:?}/lib/HookKit.framework"
}

# roothide: iOS 15-17, random-named jbroot (no /var/jb). Requires the
# roothide theos fork (THEOS_PACKAGE_SCHEME=roothide) + libroothide; the
# Makefile drops RootBridge and defines SHADOW_ROOTHIDE for this scheme.
build_roothide() {
    make clean &&
    test -d "${THEOS:?}/vendor/mod/roothide" && \
    local BAK=/tmp/hookkit-control-roothide.bak.$$
    trap "mv $BAK control 2>/dev/null || true" EXIT
    cp control "$BAK"
    sed -e 's/, me.jjolano.fmwk.rootbridge//' -e 's/firmware (>= 9.0)/firmware (>= 15.0)/' control > control.tmp && mv control.tmp control
    THEOS_PACKAGE_SCHEME=roothide ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:17.0 make package FINALPACKAGE=1 &&
    cp -p "$(cat .theos/last_package)" build/

    rm -rf "${THEOS:?}/lib/HookKit.framework"
}

case ${1:-all} in
    rootless) build_rootless ;;
    rooted) build_rooted ;;
    roothide) build_roothide ;;
    all) build_rootless; build_rooted; build_roothide ;;
    *) echo "usage: $0 [all|rootless|rooted|roothide]" >&2; exit 1 ;;
esac
