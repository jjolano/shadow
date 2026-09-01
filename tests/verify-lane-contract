#!/bin/sh
# Keep build lanes and package control templates aligned.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$ROOT/lanes.sh"

status=0

fail() {
    echo "LANE CONTRACT: $*" >&2
    status=1
}

for lane in rootful-legacy rootful-modern rootless roothide; do
    control="$ROOT/control.$lane"
    [ -f "$control" ] || { fail "$lane has no control file"; continue; }

    package=$(shadow_lane_field "$lane" PACKAGE)
    floor=$(shadow_lane_field "$lane" FLOOR)
    ceiling=$(shadow_lane_field "$lane" CEILING)
    target=$(shadow_lane_field "$lane" TARGET)
    sdk=${target#iphone:clang:}
    sdk=${sdk%%:*}
    deps=$(sed -n 's/^Depends: //p' "$control")
    actual_package=$(sed -n 's/^Package: //p' "$control")

    [ -n "$sdk" ] && [ "$sdk" != "$target" ] || fail "$lane has no SDK in TARGET '$target'"
    [ "$actual_package" = "$package" ] || fail "$lane package '$actual_package' != '$package'"
    # The rootless/RootHide Theos schemes rewrite the control template's
    # iphoneos-arm architecture during packaging.  The final package
    # architecture is checked by scripts/check-compat.sh against PACKAGE_ARCH.

    case "$deps" in
        *"firmware (>= $floor)"*) ;;
        *) fail "$lane lacks firmware >= $floor" ;;
    esac

    if [ -n "$ceiling" ]; then
        case "$deps" in
            *"firmware (<< $ceiling)"*) ;;
            *) fail "$lane lacks firmware << $ceiling" ;;
        esac
    fi
done

[ "$status" -eq 0 ] || exit "$status"
echo "OK: build lanes and package metadata agree"
