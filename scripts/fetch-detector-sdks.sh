#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEPS="$ROOT/.detector-deps"
mkdir -p "$DEPS"

SDK=${1:-all}

if { [ "$SDK" = all ] || [ "$SDK" = iossecuritysuite ]; } &&
    [ ! -f "$DEPS/IOSSecuritySuite/IOSSecuritySuite/IOSSecuritySuite.swift" ]; then
    git clone --depth 1 --branch 2.3.0 https://github.com/securing/IOSSecuritySuite.git "$DEPS/IOSSecuritySuite"
fi

if { [ "$SDK" = all ] || [ "$SDK" = freerasp ]; } &&
    [ ! -d "$DEPS/Free-RASP-iOS-6.4.0/Talsec/TalsecRuntime.xcframework" ]; then
    git init "$DEPS/Free-RASP-iOS-6.4.0"
    git -C "$DEPS/Free-RASP-iOS-6.4.0" remote add origin https://github.com/talsec/Free-RASP-iOS.git
    git -C "$DEPS/Free-RASP-iOS-6.4.0" fetch --depth 1 origin 3c51e01d07b14d6cfd0d2cbf937e7169621f0c41
    git -C "$DEPS/Free-RASP-iOS-6.4.0" checkout --detach FETCH_HEAD
fi

if { [ "$SDK" = all ] || [ "$SDK" = dtt ]; } &&
    [ ! -f "$DEPS/DTTJailbreakDetection/Sources/DTTJailbreakDetection/DTTJailbreakDetection.m" ]; then
    git init "$DEPS/DTTJailbreakDetection"
    git -C "$DEPS/DTTJailbreakDetection" remote add origin https://github.com/thii/DTTJailbreakDetection.git
    git -C "$DEPS/DTTJailbreakDetection" fetch --depth 1 origin cedd42473963615bd147c74e04346a2fd7f0d9b4
    git -C "$DEPS/DTTJailbreakDetection" checkout --detach FETCH_HEAD
fi
