#!/bin/sh
# Verifies the hook→engine coverage matrix embedded in coverage-report.sh
# against the ACTUAL engine call sites in ShadowCore.dylib/hooks/*.x.
#
# For every matrix entry whose group list consists of hook-file basenames
# (the hook-facing entry points), two drift directions are checked:
#   - a hook file calling the entry point without being listed → MATRIX DRIFT
#     (a hook reached an untracked engine API, or the matrix is stale)
#   - a listed hook file with no call site for the entry point → MATRIX STALE
# Entries with non-hook group lists (backend/ruleset/internal) are skipped.
set -e

MATRIX=tests/coverage-report.sh
HOOKDIR=ShadowCore.dylib/hooks
rc=0
entries=$(mktemp)
trap 'rm -f "$entries"' 0 HUP INT TERM

awk -F'"' '
    /^report / && $6 ~ /\[/ {
        pattern = $4
        groups = $6
        gsub(/[\[\]]/, "", groups)
        print pattern "|" groups
    }
' "$MATRIX" >"$entries"

while IFS='|' read -r pattern groups; do
    ok=1

    # Skip entries whose groups are not hook-file basenames.
    for g in $groups; do
        if [ ! -f "$HOOKDIR/$g.x" ] && ! find "$HOOKDIR" -maxdepth 2 -name "$g.x" | grep -q .; then
            ok=0
            break
        fi
    done

    [ "$ok" = 0 ] && continue

    for g in $groups; do
        f=$(find "$HOOKDIR" -maxdepth 2 -name "$g.x" | head -1)

        if [ -z "$f" ] || ! grep -q "$pattern" "$f"; then
            echo "MATRIX STALE: $g.x listed for $pattern but has no call site"
            rc=1
        fi
    done

    for f in "$HOOKDIR"/*.x "$HOOKDIR"/*/*.x; do
        [ -f "$f" ] || continue
        base=$(basename "$f" .x)

        if grep -q "$pattern" "$f" && ! echo " $groups " | grep -q " $base "; then
            echo "MATRIX DRIFT: $base.x calls $pattern but is not in the matrix"
            rc=1
        fi
    done
done <"$entries"

if sed -n '/^void shdw_detector_detected/,/^}$/p' ShadowCore.dylib/dylib.x |
    grep -q NSUserDefaults; then
    echo 'REENTRANCY RISK: detector escalation performs synchronous preferences I/O'
    exit 1
fi

exit $rc
