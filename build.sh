#!/usr/bin/env bash
set -e

PWD=$(dirname -- "$0")
cd $PWD

# create fresh build directory
rm -rf $PWD/build
mkdir -p $PWD/build

# build main project (rootless ver.)
make clean &&
THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:14.0 make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

rm -rf $THEOS/lib/HookKit.framework

# build main project (rooted ver.)
make clean &&
make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

rm -rf $THEOS/lib/HookKit.framework

# build modules
for d in Modules/*.bundle ; do
    (cd $d && make clean && make package FINALPACKAGE=1 && cp -p "`ls -dtr1 packages/* | tail -1`" ../../build/) || true
    (cd $d && make clean && THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:latest:14.0 make package FINALPACKAGE=1 && cp -p "`ls -dtr1 packages/* | tail -1`" ../../build/) || true
done
