#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${THEOS:?THEOS must point to Theos}"

"$ROOT/scripts/fetch-detector-sdks.sh" iossecuritysuite
"$ROOT/scripts/fetch-detector-sdks.sh" dtt
"$ROOT/scripts/fetch-detector-sdks.sh" freerasp
make -C "$ROOT/DetectorHarness" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/DetectorRunners/IOSSecuritySuite" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/DetectorRunners/DTTJailbreakDetection" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
make -C "$ROOT/DetectorRunners/FreeRASP" package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
