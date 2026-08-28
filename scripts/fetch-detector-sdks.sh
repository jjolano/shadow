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
    [ ! -d "$DEPS/Free-RASP-iOS-7.1.2/Talsec/TalsecRuntime.xcframework" ]; then
    git init "$DEPS/Free-RASP-iOS-7.1.2"
    git -C "$DEPS/Free-RASP-iOS-7.1.2" remote add origin https://github.com/talsec/Free-RASP-iOS.git
    git -C "$DEPS/Free-RASP-iOS-7.1.2" fetch --depth 1 origin a004c0d3b4bd6f0ef19b8c919e900fa3821a6fc0
    git -C "$DEPS/Free-RASP-iOS-7.1.2" checkout --detach FETCH_HEAD
fi

if { [ "$SDK" = all ] || [ "$SDK" = dtt ]; } &&
    [ ! -f "$DEPS/DTTJailbreakDetection/Sources/DTTJailbreakDetection/DTTJailbreakDetection.m" ]; then
    git init "$DEPS/DTTJailbreakDetection"
    git -C "$DEPS/DTTJailbreakDetection" remote add origin https://github.com/thii/DTTJailbreakDetection.git
    git -C "$DEPS/DTTJailbreakDetection" fetch --depth 1 origin cedd42473963615bd147c74e04346a2fd7f0d9b4
    git -C "$DEPS/DTTJailbreakDetection" checkout --detach FETCH_HEAD
fi

# ponytail: roothider is a single main.m, no SPM — clone only for reference, runner is native
if { [ "$SDK" = all ] || [ "$SDK" = roothider ]; } &&
    [ ! -f "$DEPS/JailbreakDetector/main.m" ]; then
    git clone --depth 1 https://github.com/roothider/JailbreakDetector.git "$DEPS/JailbreakDetector"
fi

if { [ "$SDK" = all ] || [ "$SDK" = bat ]; } &&
    [ ! -f "$DEPS/BATJailbreakGuard/Package.swift" ]; then
    git clone --depth 1 https://github.com/Basilabt/BATJailbreakGuard.git "$DEPS/BATJailbreakGuard"
fi

if { [ "$SDK" = all ] || [ "$SDK" = safetynet ]; } &&
    [ ! -f "$DEPS/SafetyNet/Package.swift" ]; then
    git clone --depth 1 https://github.com/DipakPanchasara/SafetyNet.git "$DEPS/SafetyNet"
fi

if { [ "$SDK" = all ] || [ "$SDK" = devicesecuritykit ]; } &&
    [ ! -f "$DEPS/DeviceSecurityKit/Package.swift" ]; then
    git clone --depth 1 https://github.com/galahador/DeviceSecurityKit.git "$DEPS/DeviceSecurityKit"
fi

if { [ "$SDK" = all ] || [ "$SDK" = jailmonkey ]; } &&
    [ ! -f "$DEPS/JailMonkey/JailMonkey/JailMonkey.m" ]; then
    git clone --depth 1 https://github.com/GantMan/JailMonkey.git "$DEPS/JailMonkey"
fi
