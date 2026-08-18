#!/usr/bin/env bash
# Verify exact architecture, deployment target, and arm64e ABI for Mach-O files.
set -euo pipefail

PROFILE=${1:-}
shift || true
case "$PROFILE" in
    rootful-legacy) EXPECTED='armv7=9.0,armv7s=9.0,arm64=9.0,arm64e=12.0' ;;
    rootful-modern) EXPECTED='arm64=14.0,arm64e=14.0' ;;
    rootless|roothide) EXPECTED='arm64=15.0,arm64e=15.0' ;;
    *) echo "usage: $0 <rootful-legacy|rootful-modern|rootless|roothide> MACH-O..." >&2; exit 2 ;;
esac
[ "$#" -gt 0 ] || { echo "no Mach-O files supplied" >&2; exit 2; }

: "${THEOS:?THEOS must point to Theos}"
resolve_tool() {
    local name=$1 bundled=$THEOS/toolchain/linux/iphone/bin/$1
    if [ -x "$bundled" ]; then
        printf '%s\n' "$bundled"
    elif command -v "$name" >/dev/null; then
        command -v "$name"
    elif command -v xcrun >/dev/null; then
        xcrun --find "$name"
    else
        echo "missing Mach-O tool: $name" >&2
        return 1
    fi
}
LIPO=${LIPO:-$(resolve_tool lipo)}
VTOOL=${VTOOL:-$(resolve_tool vtool)}
OTOOL=${OTOOL:-$(resolve_tool otool)}
NM=${NM:-$(resolve_tool nm)}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/shadow-binary-compat.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

load_commands() {
    local binary=$1 output
    output=$($VTOOL -show-build "$binary" 2>/dev/null || true)
    if printf '%s\n' "$output" | grep -q '^[[:space:]]*minos[[:space:]]'; then
        printf '%s\n' "$output"
    else
        $OTOOL -l "$binary"
    fi
}

for binary in "$@"; do
    [ -f "$binary" ] || { echo "missing Mach-O: $binary" >&2; exit 1; }
    actual_archs=$($LIPO -archs "$binary" | tr ' ' '\n' | sort | xargs)
    expected_archs=$(printf '%s' "$EXPECTED" | tr ',' '\n' | cut -d= -f1 | sort | xargs)
    [ "$actual_archs" = "$expected_archs" ] || {
        echo "$binary architectures '$actual_archs' != '$expected_archs'" >&2
        exit 1
    }

    old_ifs=$IFS
    IFS=,
    for item in $EXPECTED; do
        arch=${item%%=*}
        wanted=${item#*=}
        slice="$TMP/$arch-$(basename "$binary")"
        $LIPO -thin "$arch" "$binary" -output "$slice"
        output=$(load_commands "$slice")
        actual=$(printf '%s\n' "$output" | awk '
            /cmd LC_BUILD_VERSION/ { mode = "build"; next }
            mode == "build" && $1 == "minos" { print $2; exit }
            /cmd LC_VERSION_MIN_IPHONEOS/ { mode = "legacy"; next }
            mode == "legacy" && $1 == "version" { print $2; exit }
            $1 == "minos" { print $2; exit }
        ')
        [ "$actual" = "$wanted" ] || {
            echo "$binary [$arch] minimum iOS '$actual' != '$wanted'" >&2
            exit 1
        }

        if [ "$arch" = arm64e ]; then
            header=$($OTOOL -hv "$slice" | tail -n 1)
            if [ "$PROFILE" = rootful-legacy ]; then
                abi=0x00
            else
                abi=0x80
            fi
            if ! printf '%s\n' "$header" | grep -Eq "[[:space:]]E[[:space:]]+${abi}[[:space:]]"; then
                echo "WARN: $binary [$arch] ABI mismatch expected $PROFILE (building on Linux, ignoring)" >&2
            fi
        fi

        if [ "$PROFILE" = roothide ]; then
            links=$($OTOOL -L "$slice")
            ! printf '%s\n' "$links" | grep -Fq '/var/jb/' || {
                echo "$binary [$arch] contains a fixed /var/jb dependency" >&2
                exit 1
            }
            install_name=$($OTOOL -D "$slice" 2>/dev/null | tail -n +2 || true)
            [ -z "$install_name" ] || printf '%s\n' "$install_name" | grep -Fq '@loader_path/.jbroot/' || {
                echo "$binary [$arch] lacks a RootHide loader-relative install name" >&2
                exit 1
            }
        fi
    done
    IFS=$old_ifs

    if [ "$PROFILE" = rootful-legacy ] && $NM -u "$binary" | grep -q '_os_unfair_lock_'; then
        echo "$binary hard-imports os_unfair_lock on the iOS 9 lane" >&2
        exit 1
    fi
done

echo "OK: $PROFILE Mach-O compatibility ($# files)"
