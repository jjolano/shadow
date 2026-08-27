#!/usr/bin/env bash
# Compare detector-facing public SDK APIs with the iOS 15 rootless baseline.
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

reviewed_delta() { # <surface> <symbol>
    case "$1:$2" in
        objc-runtime:objc_enumerateClasses)
            rg -Fq 'dlsym(RTLD_DEFAULT, "objc_enumerateClasses")' \
                "$ROOT/ShadowCore.dylib/hooks/Runtime/objc_hidetweakclasses.x" || return 1
            echo "runtime-gated in ShadowCore.dylib/hooks/Runtime/objc_hidetweakclasses.x"
            ;;
        *) return 1 ;;
    esac
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
    esac
}

BASE_SDK=$(sdk_path "$BASELINE")
[[ -d "$BASE_SDK" ]] || { echo "missing baseline SDK: $BASE_SDK" >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/shadow-sdk-audit.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SURFACES=(objc-runtime dyld dlfcn devicecheck)

for surface in "${SURFACES[@]}"; do
    emit_surface "$BASE_SDK" "$surface" "$TMP/base-$surface"
done

failed=0
echo "SDK detector-surface audit (baseline iPhoneOS$BASELINE)"

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
                printf 'iPhoneOS%s REVIEWED %-13s %s (%s)\n' "$target" "$surface" "$symbol" "$note"
            else
                printf 'iPhoneOS%s UNREVIEWED %-11s %s\n' "$target" "$surface" "$symbol" >&2
                failed=1
            fi
        done < <(comm -13 "$TMP/base-$surface" "$current")
    done

    [[ $found -eq 1 ]] || echo "iPhoneOS$target: no new public detector-facing APIs"
done

[[ $failed -eq 0 ]] || {
    echo "Review each unreviewed API before adding a policy or hook; never fabricate DeviceCheck/App Attest artifacts." >&2
    exit 1
}

echo "OK: every new public detector-facing API has an explicit review"
