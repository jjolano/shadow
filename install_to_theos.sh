#!/bin/sh
set -e
rm -rf "$THEOS/lib/Shadow.framework"
rm -rf "$THEOS/include/Shadow"
mkdir -p "$THEOS/lib/Shadow.framework"
mkdir -p "$THEOS/include/Shadow"
cp -v fmwk/Shadow.tbd "$THEOS/lib/Shadow.framework/"
cp -v fmwk/*.h "$THEOS/include/Shadow/"
