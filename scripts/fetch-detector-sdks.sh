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

if { [ "$SDK" = all ] || [ "$SDK" = jailbreakdetector ]; } &&
    [ ! -f "$DEPS/JailbreakDetector.swift/Sources/JailbreakDetector/JailbreakDetector.swift" ]; then
    git init "$DEPS/JailbreakDetector.swift"
    git -C "$DEPS/JailbreakDetector.swift" remote add origin https://github.com/conmulligan/JailbreakDetector.swift.git
    git -C "$DEPS/JailbreakDetector.swift" fetch --depth 1 origin b6afe56380922188e60d14e49bea238c3de2f487
    git -C "$DEPS/JailbreakDetector.swift" checkout --detach FETCH_HEAD
fi

if { [ "$SDK" = all ] || [ "$SDK" = securitytoolkit ]; } &&
    [ ! -f "$DEPS/iOS-Security-Toolkit/Sources/ThreatDetectionCenter.swift" ]; then
    git init "$DEPS/iOS-Security-Toolkit"
    git -C "$DEPS/iOS-Security-Toolkit" remote add origin https://github.com/EXXETA/iOS-Security-Toolkit.git
    git -C "$DEPS/iOS-Security-Toolkit" fetch --depth 1 origin 1b310d29121f3d800367eb47fbeac9643225ea4c
    git -C "$DEPS/iOS-Security-Toolkit" checkout --detach FETCH_HEAD
fi

if { [ "$SDK" = all ] || [ "$SDK" = freerasp ]; } &&
    [ ! -d "$DEPS/Free-RASP-iOS-6.4.0/Talsec/TalsecRuntime.xcframework" ]; then
    git init "$DEPS/Free-RASP-iOS-6.4.0"
    git -C "$DEPS/Free-RASP-iOS-6.4.0" remote add origin https://github.com/talsec/Free-RASP-iOS.git
    git -C "$DEPS/Free-RASP-iOS-6.4.0" fetch --depth 1 origin refs/tags/6.4.0
    git -C "$DEPS/Free-RASP-iOS-6.4.0" checkout --detach FETCH_HEAD
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
    # Pin v.0.40.0 (matches the "0.40.0-filtered" harness label): later
    # upstream adds newer-Swift concurrency the theos Swift 5.8 frontend
    # cannot compile (signal 4 on implicit _Concurrency imports).
    git clone --depth 1 --branch v.0.40.0 https://github.com/galahador/DeviceSecurityKit.git "$DEPS/DeviceSecurityKit"
fi

if { [ "$SDK" = all ] || [ "$SDK" = jailmonkey ]; } &&
    [ ! -f "$DEPS/JailMonkey/JailMonkey/JailMonkey.m" ]; then
    git clone --depth 1 --branch v2.8.5 https://github.com/GantMan/jail-monkey.git "$DEPS/JailMonkey"
fi

if { [ "$SDK" = all ] || [ "$SDK" = isjailbroken ]; } &&
    [ ! -f "$DEPS/isJailbroken/isJailbroken/JB.m" ]; then
    git init "$DEPS/isJailbroken"
    git -C "$DEPS/isJailbroken" remote add origin https://github.com/avltree9798/isJailbroken.git
    git -C "$DEPS/isJailbroken" fetch --depth 1 origin 60a5f55965c7e44ab74d0414652ff4df55045c1f
    git -C "$DEPS/isJailbroken" checkout --detach FETCH_HEAD
fi

# ponytail: SwiftyJBD is a two-method Swift fragment (no enclosing type) — clone
# for reference; the runner wraps JailBreak.swift into a type at build time.
if { [ "$SDK" = all ] || [ "$SDK" = swiftyjbd ]; } &&
    [ ! -f "$DEPS/SwiftyJBD/JailBreak.swift" ]; then
    git init "$DEPS/SwiftyJBD"
    git -C "$DEPS/SwiftyJBD" remote add origin https://github.com/TheSwiftyCoder/JailBreak-Detection.git
    git -C "$DEPS/SwiftyJBD" fetch --depth 1 origin 6f5f1d9622934c048c64c8b6a68942d2ece3a5f0
    git -C "$DEPS/SwiftyJBD" checkout --detach FETCH_HEAD
fi
