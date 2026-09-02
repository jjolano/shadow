#!/usr/bin/env bash
# Verify package metadata, contents, slices, deployment targets, and arm64e ABI.
set -euo pipefail

PROFILE=${1:-}
ARTIFACT=${2:-}
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

# Keep the package contract with the build-lane contract.  This script runs
# after packaging, so a mismatched control file cannot silently broaden a
# lane's supported iOS range.
. "$ROOT/build-support/lanes.sh"

case "$PROFILE" in
    rootful-legacy|rootful-modern|rootless|roothide) ;;
    *) echo "usage: $0 <rootful-legacy|rootful-modern|rootless|roothide> ARTIFACT.deb" >&2; exit 2 ;;
esac

PACKAGE=$(shadow_lane_field "$PROFILE" PACKAGE)
PACKAGE_ARCH=$(shadow_lane_field "$PROFILE" PACKAGE_ARCH)
FLOOR=$(shadow_lane_field "$PROFILE" FLOOR)
CEILING=$(shadow_lane_field "$PROFILE" CEILING)

[ -f "$ARTIFACT" ] || { echo "artifact not found: $ARTIFACT" >&2; exit 2; }
: "${THEOS:?THEOS must point to Theos}"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/shadow-compat.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
dpkg-deb -x "$ARTIFACT" "$TMP/root"

actual_package=$(dpkg-deb -f "$ARTIFACT" Package)
actual_arch=$(dpkg-deb -f "$ARTIFACT" Architecture)
depends=$(dpkg-deb -f "$ARTIFACT" Depends)
[ "$actual_package" = "$PACKAGE" ] || { echo "package '$actual_package' != '$PACKAGE'" >&2; exit 1; }
[ "$actual_arch" = "$PACKAGE_ARCH" ] || { echo "architecture '$actual_arch' != '$PACKAGE_ARCH'" >&2; exit 1; }
printf '%s\n' "$depends" | grep -Fq "firmware (>= $FLOOR)" || { echo "missing firmware >= $FLOOR" >&2; exit 1; }
[ -z "$CEILING" ] || printf '%s\n' "$depends" | grep -Fq "firmware (<< $CEILING)" || { echo "missing firmware << $CEILING" >&2; exit 1; }

if [ "$PROFILE" = rootful-legacy ]; then
    for package in com.opa334.altlist.legacy com.opa334.libsandy.legacy me.jjolano.fmwk.hookkit.legacy; do
        printf '%s\n' "$depends" | grep -Fq "$package" || { echo "missing legacy dependency: $package" >&2; exit 1; }
    done
fi

find_one() { # find arguments
    local matches
    matches=$(find "$TMP/root" "$@" -print)
    [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || {
        echo "expected one package path matching: $*" >&2
        return 1
    }
    printf '%s\n' "$matches"
}

SHADOW=$(find_one -type f -path '*/Shadow.framework/Shadow')
TWEAK=$(find_one -type f -path '*/DynamicLibraries/Shadow.dylib')
CORE=$(find_one -type f -path '*/usr/lib/ShadowCore.dylib')
SETTINGS=$(find_one -type f -path '*/PreferenceBundles/ShadowSettings.bundle/ShadowSettings')
SHDW=$(find_one -type f -path '*/usr/local/bin/shdw')

"$(dirname "$0")/check-binary-compat.sh" "$PROFILE" "$SHADOW" "$TWEAK" "$CORE" "$SETTINGS" "$SHDW"

WATCHER=$(find_one -type f -name me.jjolano.shadow.watcher.plist)
[ -n "$WATCHER" ]
daemon=$(find "$TMP/root" -type f -path '*/usr/libexec/shadowd' -print)
daemon_plist=$(find "$TMP/root" -type f -name me.jjolano.shadow.plist -print)
[ -z "$daemon$daemon_plist" ] || { echo "package contains removed shadowd backend" >&2; exit 1; }

echo "OK: $PROFILE package metadata, contents, slices, deployment targets, and ABI"
