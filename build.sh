#!/usr/bin/env bash
set -e

PWD=$(dirname -- "$0")
cd $PWD

# create fresh build directory
rm -rf $PWD/build
mkdir -p $PWD/build

# build main project (rootless ver.)
make clean &&
THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:16.5:12.0 make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

rm -rf $THEOS/lib/HookKit.framework

# build main project (rooted ver.)
make clean &&
ARCHS="arm64 arm64e" TARGET=iphone:clang:16.5:12.0 make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

rm -rf $THEOS/lib/HookKit.framework

# build legacy ver. (32-bit devices: iOS 9.0+)
cp -p control control.bak
sed -i 's/firmware (>= 12.0)/firmware (>= 9.0)/' control
make clean &&
ARCHS="armv7 armv7s" TARGET=iphone:clang:16.5:9.0 make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/
mv control.bak control

rm -rf $THEOS/lib/HookKit.framework
