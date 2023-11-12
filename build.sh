#!/usr/bin/env bash
set -e

PWD=$(dirname -- "$0")
cd $PWD

# create fresh build directory
rm -rf $PWD/build
mkdir -p $PWD/build

# build main project (rootless ver.)
make clean &&
THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" TARGET=iphone:clang:14.5:14.0 make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

# build main project (roothide ver.)
make clean &&
THEOS_PACKAGE_SCHEME=roothide ARCHS="arm64 arm64e" TARGET=iphone:clang:14.5:14.0 make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

rm -rf $THEOS/lib/Shadow.framework

# build main project (rooted ver.)
make clean &&
make package FINALPACKAGE=1 &&
cp -p "`ls -dtr1 packages/* | tail -1`" $PWD/build/

rm -rf $THEOS/lib/Shadow.framework
