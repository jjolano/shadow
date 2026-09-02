#!/usr/bin/env bash
# Build dyldprobe. Default: debs for both flavors, collected in build/.
#   ./build.sh ipa — sideloadable .ipa (Payload/dyldprobe.app) per flavor
#   instead, for on-device verification through the normal user app
#   channel: sideloading installs under /var/containers/Bundle/Application,
#   which Shadow's ctor injects, unlike the /Applications deb install.
set -e
PWD=$(dirname -- "$0")
cd $PWD

MODE="${1:-deb}"
rm -rf build && mkdir -p build

if [ "$MODE" = "ipa" ]; then
    # Theos' PACKAGE_FORMAT=ipa stages the app bundle, then zips
    # Payload/dyldprobe.app. Signing stays ad-hoc/unsigned — developer
    # sideload use only (Sideloadly/AltStore), not a release artifact.
    make clean >/dev/null 2>&1 || true
    make ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0 PACKAGE_FORMAT=ipa package FINALPACKAGE=1 >/dev/null
    cp -p "`ls -dtr1 packages/*.ipa | tail -1`" build/dyldprobe-rooted.ipa

    make clean >/dev/null 2>&1 || true
    THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0 PACKAGE_FORMAT=ipa make package FINALPACKAGE=1 >/dev/null
    cp -p "`ls -dtr1 packages/*.ipa | tail -1`" build/dyldprobe-rootless.ipa

    echo "Sideload build/dyldprobe-rooted.ipa or build/dyldprobe-rootless.ipa"
    echo "(ad-hoc/unsigned; dev use only). Installs under"
    echo "/var/containers/Bundle/Application, so Shadow's ctor injects it."
    ls -la build/
    exit 0
fi

make clean >/dev/null 2>&1 || true
make ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0 package FINALPACKAGE=1 >/dev/null
cp -p "`ls -dtr1 packages/* | tail -1`" build/

make clean >/dev/null 2>&1 || true
THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0 make package FINALPACKAGE=1 >/dev/null
cp -p "`ls -dtr1 packages/* | tail -1`" build/
ls -la build/
