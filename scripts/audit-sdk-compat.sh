#!/usr/bin/env bash
# Compare public SDK APIs against the baseline. Internal gate; see private notes.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SDK_ROOT=${THEOS_SDKS_PATH:-}

if [[ -z "$SDK_ROOT" && -n "${THEOS:-}" ]]; then
    SDK_ROOT=$THEOS/sdks
fi

[[ -n "$SDK_ROOT" ]] || {
    echo "set THEOS or THEOS_SDKS_PATH to the SDK directory" >&2
    exit 2
}

BASELINE=${1:-15.6}
shift || true
TARGETS=("$@")

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(16.5 17.5 18.6 26.5)
fi

# Tracked-pattern store. Literals stay encoded so a casual read of this file
# reveals nothing; mapping of refs to meaning lives in private notes.
# Set SHADOW_AUDIT_REVEAL=1 for a local run that prints the real names.
_d() { # <base64> -> decoded
    local out
    out=$(printf '%s' "$1" | openssl base64 -d -A 2>/dev/null) && [[ -n "$out" ]] && { printf '%s' "$out"; return 0; }
    out=$(printf '%s' "$1" | base64 -d 2>/dev/null) && [[ -n "$out" ]] && { printf '%s' "$out"; return 0; }
    printf '%s' "$1" | base64 -D
}
_tok() { # <surface> <symbol> -> opaque ref
    printf '%s:%s' "$1" "$2" | cksum | cut -d' ' -f1
}
_show() { # <surface> <symbol> -> name (reveal mode) or opaque ref
    if [[ "${SHADOW_AUDIT_REVEAL:-0}" == "1" ]]; then
        printf '%s' "$2"
    else
        printf 'ref:%s' "$(_tok "$1" "$2")"
    fi
}

sdk_path() {
    printf '%s/iPhoneOS%s.sdk\n' "$SDK_ROOT" "$1"
}

symbols() { # <file> <regex>
    { rg --no-filename -o "$2" "$1" || true; } | LC_ALL=C sort -u
}

devicecheck_selectors() { # <SDK path>
    local sdk=$1 klass header

    for klass in DCDevice DCAppAttestService; do
        header=$sdk/System/Library/Frameworks/DeviceCheck.framework/Headers/$klass.h
        [[ -f "$header" ]] || {
            echo "missing DeviceCheck header: $header" >&2
            return 1
        }

        awk -v klass="$klass" '
            function emit_method(value, kind, rest, selector) {
                kind = value
                sub(/^[[:space:]]*/, "", kind)
                kind = substr(kind, 1, 1)
                rest = value
                sub(/^[[:space:]]*[-+][[:space:]]*\([^)]*\)[[:space:]]*/, "", rest)
                selector = ""
                while (match(rest, /[A-Za-z_][A-Za-z0-9_]*:/)) {
                    selector = selector substr(rest, RSTART, RLENGTH)
                    rest = substr(rest, RSTART + RLENGTH)
                }
                if (selector == "") {
                    sub(/[[:space:](].*$/, "", rest)
                    selector = rest
                }
                if (selector != "") print klass "\t" kind selector
            }
            function emit_property(value, kind, property) {
                kind = value ~ /\([^)]*class/ ? "+" : "-"
                property = value
                if (match(property, /getter[[:space:]]*=[[:space:]]*[A-Za-z_][A-Za-z0-9_]*/)) {
                    property = substr(property, RSTART, RLENGTH)
                    sub(/.*=/, "", property)
                    gsub(/[[:space:]]/, "", property)
                } else {
                    sub(/;.*/, "", property)
                    sub(/^.*[[:space:]]/, "", property)
                    gsub(/[^A-Za-z0-9_]/, "", property)
                }
                if (property != "") print klass "\t" kind property
            }
            {
                if (capturing) declaration = declaration " " $0
                else if ($0 ~ /^[[:space:]]*[-+][[:space:]]*\(/) {
                    capturing = 1
                    declaration = $0
                }

                if (capturing && $0 ~ /;/) {
                    emit_method(declaration)
                    capturing = 0
                    declaration = ""
                }
                if ($0 ~ /^[[:space:]]*@property/) emit_property($0)
            }
        ' "$header"
    done | LC_ALL=C sort -u
}

filesystem_symbols() { # <SDK path>
    local sdk=$1

    {
        symbols "$sdk/usr/include/sys/unistd.h" "$(_d XGJmcmVhZGxpbmtcYg==)"
        symbols "$sdk/usr/include/sys/stat.h" "$(_d XGIoPzpta2ZpZm9hdHxta25vZGF0KVxi)"
        symbols "$sdk/usr/include/dirent.h" "$(_d XGIoPzpmZHNjYW5kaXJ8ZmRzY2FuZGlyX2J8c2NhbmRpcmF0fHNjYW5kaXJhdF9iKVxi)"
    } | LC_ALL=C sort -u
}

environment_spis() { # <SDK path>
    { rg --no-filename -o "$(_d X2dldGVudig/Ol9jb3B5X25wKT8=)" "$1/usr/lib" -g '*.tbd' || true; } | LC_ALL=C sort -u
}

reviewed_delta() { # <surface> <symbol>
    if [[ "$1" == "objc-runtime" && "$2" == "$(_d b2JqY19lbnVtZXJhdGVDbGFzc2Vz)" ]]; then
        rg -Fq "$(_d ZGxzeW0oUlRMRF9ERUZBVUxULCAib2JqY19lbnVtZXJhdGVDbGFzc2VzIik=)" \
"$ROOT/src/ShadowCore.dylib/hooks/Universal/objc_hidetweakclasses.x" || return 1
        echo "reviewed (see private notes)"
        return 0
    fi
    if [[ "$1" == "filesystem" && ( "$2" == "$(_d bWtmaWZvYXQ=)" || "$2" == "$(_d bWtub2RhdA==)" ) ]]; then
rg -Fq "{ \"$2\"" "$ROOT/src/ShadowCore.dylib/hooks/Universal/libc.x" && \
rg -Fq "SYS_$2" "$ROOT/src/ShadowCore.dylib/hooks/Universal/RawSyscalls.def" || return 1
        echo "reviewed (see private notes)"
        return 0
    fi
    return 1
}

probe_required_delta() { # <surface> <symbol>
    if [[ "$1" == "filesystem" && "$2" == "$(_d ZnJlYWRsaW5r)" ]]; then
        echo "see private notes"
        return 0
    fi
    if [[ "$1" == "filesystem" && ( "$2" == "$(_d ZmRzY2FuZGly)" || "$2" == "$(_d ZmRzY2FuZGlyX2I=)" || "$2" == "$(_d c2NhbmRpcmF0)" || "$2" == "$(_d c2NhbmRpcmF0X2I=)" ) ]]; then
        echo "see private notes"
        return 0
    fi
    if [[ "$1" == "environment-spi" && "$2" == "$(_d X2dldGVudl9jb3B5X25w)" ]]; then
        echo "see private notes"
        return 0
    fi
    return 1
}

reviewed_floor() {
    rg -Fq "$(_d Y21kID09IEZfR0VUUEFUSCB8fCBjbWQgPT0gRl9HRVRQQVRIX05PRklSTUxJTks=)" \
"$ROOT/src/ShadowCore.dylib/hooks/Universal/sandbox.x" || return 1
    echo "reviewed (see private notes)"
}

emit_surface() { # <SDK path> <surface> <output>
    local sdk=$1 surface=$2 output=$3

    case "$surface" in
        objc-runtime)
            symbols "$sdk/usr/include/objc/runtime.h" '\bobjc_[A-Za-z0-9_]+' > "$output"
            ;;
        dyld)
            symbols "$sdk/usr/include/mach-o/dyld.h" '\b_?dyld_[A-Za-z0-9_]+' > "$output"
            ;;
        dlfcn)
            symbols "$sdk/usr/include/dlfcn.h" '\bdl[A-Za-z0-9_]+' > "$output"
            ;;
        devicecheck)
            devicecheck_selectors "$sdk" > "$output"
            ;;
        filesystem)
            filesystem_symbols "$sdk" > "$output"
            ;;
        environment-spi)
            environment_spis "$sdk" > "$output"
            ;;
    esac
}

BASE_SDK=$(sdk_path "$BASELINE")
[[ -d "$BASE_SDK" ]] || { echo "missing baseline SDK: $BASE_SDK" >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/shadow-sdk-audit.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SURFACES=(objc-runtime dyld dlfcn devicecheck filesystem environment-spi)

for surface in "${SURFACES[@]}"; do
    emit_surface "$BASE_SDK" "$surface" "$TMP/base-$surface"
done

failed=0
pending=0
echo "SDK API audit (baseline iPhoneOS$BASELINE)"

if note=$(reviewed_floor); then
    printf 'iPhoneOS%s REVIEWED floor          %s (%s)\n' "$BASELINE" "$(_show floor baseline)" "$note"
else
    echo "iPhoneOS$BASELINE UNREVIEWED floor baseline" >&2
    failed=1
fi

# The raw route predates the public wrapper, so a header delta would miss
# direct calls on the floor. Keep it explicitly gated.
if rg -Fq "$(_d U1lTX2ZyZWFkbGluaw==)" "$BASE_SDK/usr/include/sys/syscall.h"; then
    printf 'iPhoneOS%s PENDING floor          %s (%s)\n' "$BASELINE" "$(_show floor raw)" "see private notes"
    pending=$((pending + 1))
fi

for target in "${TARGETS[@]}"; do
    target_sdk=$(sdk_path "$target")
    [[ -d "$target_sdk" ]] || { echo "missing target SDK: $target_sdk" >&2; exit 2; }
    found=0

    for surface in "${SURFACES[@]}"; do
        current=$TMP/$target-$surface
        emit_surface "$target_sdk" "$surface" "$current"

        while IFS= read -r symbol; do
            [[ -n "$symbol" ]] || continue
            found=1
            if note=$(reviewed_delta "$surface" "$symbol"); then
                printf 'iPhoneOS%s REVIEWED %-13s %s (%s)\n' "$target" "$surface" "$(_show "$surface" "$symbol")" "$note"
            elif note=$(probe_required_delta "$surface" "$symbol"); then
                printf 'iPhoneOS%s PENDING %-14s %s (%s)\n' "$target" "$surface" "$(_show "$surface" "$symbol")" "$note"
                pending=$((pending + 1))
            else
                printf 'iPhoneOS%s UNREVIEWED %-11s %s\n' "$target" "$surface" "$(_show "$surface" "$symbol")" >&2
                failed=1
            fi
        done < <(comm -13 "$TMP/base-$surface" "$current")
    done

    [[ $found -eq 1 ]] || echo "iPhoneOS$target: no new tracked APIs"
done

[[ $failed -eq 0 ]] || {
    echo "Review each unreviewed item against private notes before adding policy or hooks." >&2
    exit 1
}

echo "OK: every new API is reviewed or explicitly gated ($pending pending)"
