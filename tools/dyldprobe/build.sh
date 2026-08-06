#!/usr/bin/env bash
# Build dyldprobe for both flavors and collect the debs.
set -e
PWD=$(dirname -- "$0")
cd $PWD
rm -rf build && mkdir -p build

make clean >/dev/null 2>&1 || true
make ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:12.0 package FINALPACKAGE=1 >/dev/null
cp -p "`ls -dtr1 packages/* | tail -1`" build/

make clean >/dev/null 2>&1 || true
THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:15.0 make package FINALPACKAGE=1 >/dev/null
cp -p "`ls -dtr1 packages/* | tail -1`" build/
ls -la build/
