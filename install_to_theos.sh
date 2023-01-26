#!/bin/sh
set -e
rm -rf "$THEOS/lib/HookKit.framework"
mkdir -p "$THEOS/lib/HookKit.framework"
cp -v "HookKit.tbd" "$THEOS/lib/HookKit.framework/HookKit.tbd"
cp -v "Headers/HookKit.h" "$THEOS/include/HookKit.h"
