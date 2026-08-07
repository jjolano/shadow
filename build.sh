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

case ${1:-all} in
    rootless) build_rootless ;;
    rooted) build_rooted ;;
    all) build_rootless; build_rooted ;;
    *) echo "usage: $0 [all|rootless|rooted]" >&2; exit 1 ;;
esac
