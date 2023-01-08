#!/bin/sh
set -e
rm -rf "$THEOS/lib/HookKit.framework"
mkdir -p "$THEOS/lib/HookKit.framework"
cp -v "Resources/HookKit.tbd" "$THEOS/lib/HookKit.framework/HookKit.tbd"
cp -v "HookKit.h" "$THEOS/include/HookKit.h"
