#!/bin/bash

PWD=$(dirname -- "$0")
cd $PWD

# create fresh build directory
rm -rf $PWD/build
mkdir -p $PWD/build

# build main project
for d in deb/iphoneos-* ; do
    (cd $d && make package FINALPACKAGE=1 && cp -p "`ls -dtr1 packages/* | tail -1`" ../../build/)
done

# build modules
for d in Modules/*.bundle ; do
    (for dd in $d/deb/iphoneos-* ; do
        (cd $dd && make package FINALPACKAGE=1 && cp -p "`ls -dtr1 packages/* | tail -1`" ../../../../build/)
    done)
done
