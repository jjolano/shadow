#!/usr/bin/env bash
set -euo pipefail
if [ "$(basename "$0")" = compat-tool ]; then
    case "$1" in
        -archs) echo "$TEST_ARCHS" ;;
        -thin) touch "$5" ;;
        -show-build|-l)
            deploy=$TEST_DEPLOY
            case "$(basename "$2")" in arm64e-*) deploy=$TEST_DEPLOY_ARM64E ;; esac
            if [ "$TEST_LANE" = rootful-legacy ]; then
                if [ "$1" = -l ]; then
                    printf 'cmd LC_VERSION_MIN_IPHONEOS\nversion %s\n' "$deploy"
                fi
            else
                printf 'cmd LC_BUILD_VERSION\nminos %s\n' "$deploy"
            fi
            ;;
        -h) printf ' 0xfeedfacf 16777228 2 %s 6 35 4320 0x00900085\n' "$TEST_ABI" ;;
        -L) printf '%s:\n\t%s (compatibility version 1.0.0)\n' "$2" "$TEST_LINK" ;;
        -D) printf '%s:\n%s\n' "$2" "$TEST_INSTALL_NAME" ;;
        -u) printf '%s\n' "$TEST_IMPORT" ;;
        *) exit 1 ;;
    esac
    exit
fi
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
touch "$TMP/binary"
. "$ROOT/build-support/lanes.sh"
ln -s "$ROOT/tests/BinaryCompatTests.sh" "$TMP/compat-tool"
export LIPO="$TMP/compat-tool"
export VTOOL=$LIPO OTOOL=$LIPO NM=$LIPO
checks=0
check() {
    local expected_status=$1 expected_output=$2 output status=0
    shift 2
    output=$(env "$@" bash "$ROOT/scripts/check-binary-compat.sh" "$TEST_LANE" "$TMP/binary" 2>&1) || status=$?
    if [ "$status" -ne "$expected_status" ] || [ "$output" != "$expected_output" ]; then
        printf 'FAIL: %s %s\nexpected (%s): %s\nactual (%s): %s\n' \
            "$TEST_LANE" "$*" "$expected_status" "$expected_output" "$status" "$output" >&2
        exit 1
    fi
    checks=$((checks + 1))
}

for TEST_LANE in rootful-legacy rootful-modern rootless roothide; do
    TEST_ARCHS=$(shadow_lane_field "$TEST_LANE" ARCHS)
    TEST_DEPLOY=$(shadow_lane_field "$TEST_LANE" DEPLOY)
    if [ -z "$TEST_DEPLOY" ]; then
        target=$(shadow_lane_field "$TEST_LANE" TARGET)
        TEST_DEPLOY=${target##*:}
    fi
    TEST_DEPLOY_ARM64E=$(shadow_lane_field "$TEST_LANE" DEPLOY_ARM64E)
    TEST_DEPLOY_ARM64E=${TEST_DEPLOY_ARM64E:-$TEST_DEPLOY}
    TEST_ABI=0x80
    wrong_abi=0x00
    if [ "$TEST_LANE" = rootful-legacy ]; then
        TEST_ABI=0x00
        wrong_abi=0x80
    fi
    export TEST_LANE TEST_ARCHS TEST_DEPLOY TEST_DEPLOY_ARM64E TEST_ABI
    export TEST_LINK=/usr/lib/libSystem.B.dylib TEST_IMPORT=_malloc
    export TEST_INSTALL_NAME=@loader_path/.jbroot/Library/Frameworks/Shadow.framework/Shadow

    check 0 "OK: $TEST_LANE Mach-O compatibility (1 files)"
    sorted_archs=$(printf '%s\n' "$TEST_ARCHS" | tr ' ' '\n' | sort | xargs)
    check 1 "$TMP/binary architectures 'x86_64' != '$sorted_archs'" TEST_ARCHS=x86_64
    for deploy in "$((${TEST_DEPLOY%%.*} - 1)).0" "$((${TEST_DEPLOY%%.*} + 1)).0"; do
        check 1 "$TMP/binary [${TEST_ARCHS%% *}] minimum iOS '$deploy' != '$TEST_DEPLOY'" TEST_DEPLOY="$deploy"
    done
    for deploy in "$((${TEST_DEPLOY_ARM64E%%.*} - 1)).0" "$((${TEST_DEPLOY_ARM64E%%.*} + 1)).0"; do
        check 1 "$TMP/binary [arm64e] minimum iOS '$deploy' != '$TEST_DEPLOY_ARM64E'" TEST_DEPLOY_ARM64E="$deploy"
    done
    check 1 "$TMP/binary [arm64e] ABI mismatch expected $TEST_LANE" TEST_ABI="$wrong_abi"
    if [ "$TEST_LANE" = rootful-legacy ]; then
        check 1 "$TMP/binary hard-imports os_unfair_lock on the iOS 9 lane" TEST_IMPORT=_os_unfair_lock_lock
    elif [ "$TEST_LANE" = roothide ]; then
        check 1 "$TMP/binary [arm64] contains a fixed /var/jb dependency" TEST_LINK=/var/jb/usr/lib/libExample.dylib
        check 1 "$TMP/binary [arm64] lacks a RootHide loader-relative install name" TEST_INSTALL_NAME=/Library/Frameworks/Shadow.framework/Shadow
    fi
done
echo "PASS: $checks binary compatibility checks"
