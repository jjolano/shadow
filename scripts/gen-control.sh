#!/usr/bin/env bash
# Render packaging/controls/control.<lane>.in to stdout, filling the fields the
# lane matrix owns (@PACKAGE@, @PACKAGE_ARCH@, @FIRMWARE@) from
# build-support/lanes.sh. Package identity, architecture and firmware window
# thus have a single source of truth -- the same fields check-compat.sh verifies
# on the built .deb -- so the control can never drift from the lane it ships as.
set -euo pipefail

LANE=${1:-}
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$ROOT/build-support/lanes.sh"

TEMPLATE="$ROOT/packaging/controls/control.$LANE.in"
[ -f "$TEMPLATE" ] || { echo "no control template for lane '$LANE'" >&2; exit 2; }

PACKAGE=$(shadow_lane_field "$LANE" PACKAGE)
PACKAGE_ARCH=$(shadow_lane_field "$LANE" PACKAGE_ARCH)
FLOOR=$(shadow_lane_field "$LANE" FLOOR)
CEILING=$(shadow_lane_field "$LANE" CEILING)

FIRMWARE="firmware (>= $FLOOR)"
[ -z "$CEILING" ] || FIRMWARE="$FIRMWARE, firmware (<< $CEILING)"

sed -e "s|@PACKAGE@|$PACKAGE|g" \
    -e "s|@PACKAGE_ARCH@|$PACKAGE_ARCH|g" \
    -e "s|@FIRMWARE@|$FIRMWARE|g" \
    "$TEMPLATE"
