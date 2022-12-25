#!/bin/sh
set -e
make clean
make FINALPACKAGE=1
cp -Rv ".theos/obj/HookKit.framework" "$THEOS/lib"
cp -v "HookKit.h" "$THEOS/include"
