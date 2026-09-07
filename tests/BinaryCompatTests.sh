#!/usr/bin/env bash
set -euo pipefail
if [ "$(basename "$0")" = compat-tool ]; then
    case "$1" in
        -archs) echo 'arm64 arm64e' ;;
        -thin) touch "$5" ;;
        -show-build) echo 'minos 15.0' ;;
        -h) printf ' 0xfeedfacf 16777228 2 %s 6 35 4320 0x00900085\n' "$TEST_ABI" ;;
        *) exit 1 ;;
    esac
    exit
fi
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
touch "$TMP/binary"
export THEOS=${THEOS:-$TMP}
ln -s "$ROOT/tests/BinaryCompatTests.sh" "$TMP/compat-tool"
export LIPO="$TMP/compat-tool"
export VTOOL=$LIPO OTOOL=$LIPO NM=$LIPO
TEST_ABI=0x80 bash "$ROOT/scripts/check-binary-compat.sh" rootless "$TMP/binary"
if TEST_ABI=0x00 bash "$ROOT/scripts/check-binary-compat.sh" rootless "$TMP/binary"; then
    echo 'FAIL: old arm64e ABI accepted for rootless' >&2
    exit 1
fi
echo 'PASS: numeric new ABI accepted; old ABI rejected'
