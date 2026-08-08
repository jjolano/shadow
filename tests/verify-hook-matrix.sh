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

awk -F'"' '
    /^report / && $6 ~ /\[/ {
        pattern = $4
        groups = $6
        gsub(/[\[\]]/, "", groups)
        print pattern "|" groups
    }
' "$MATRIX" | while IFS='|' read -r pattern groups; do
    ok=1

    # Skip entries whose groups are not hook-file basenames.
    for g in $groups; do
        if [ ! -f "$HOOKDIR/$g.x" ]; then
            ok=0
            break
        fi
    done

    [ "$ok" = 0 ] && continue

    for g in $groups; do
        if ! grep -q "$pattern" "$HOOKDIR/$g.x"; then
            echo "MATRIX STALE: $g.x listed for $pattern but has no call site"
            rc=1
        fi
    done

    for f in "$HOOKDIR"/*.x; do
        base=$(basename "$f" .x)

        if grep -q "$pattern" "$f" && ! echo " $groups " | grep -q " $base "; then
            echo "MATRIX DRIFT: $base.x calls $pattern but is not in the matrix"
            rc=1
        fi
    done
done

exit $rc
