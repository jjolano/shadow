#!/bin/sh
# The recovery harness's copy of recover_one_record (RecoveryHarness.m) must
# stay byte-identical to the daemon's (shadowd/main.m) — the copy is the test
# double, so any drift makes the harness silently test stale logic.
#
# The bodies are extracted brace-balanced from the signature to the matching
# close (the signature line itself differs by design: the harness function is
# non-static and renamed). The rest of the body must be identical, comments
# included.
set -e

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

awk '
    /^static void recover_one_record/ { found = 1; depth = 1; next }
    found {
        depth += gsub(/{/, "{")
        depth -= gsub(/}/, "}")
        if (depth <= 0) exit
        print
    }
' "$ROOT/shadowd/main.m" > /tmp/recovery-orig-body.txt

awk '
    /^void shdw_test_recover_one_record/ { found = 1; depth = 1; next }
    found {
        depth += gsub(/{/, "{")
        depth -= gsub(/}/, "}")
        if (depth <= 0) exit
        print
    }
' "$ROOT/tests/shadowd/RecoveryHarness.m" > /tmp/recovery-copy-body.txt

if diff -q /tmp/recovery-orig-body.txt /tmp/recovery-copy-body.txt > /dev/null; then
    echo "recovery copy matches shadowd/main.m"
    exit 0
fi

echo "RECOVERY COPY DRIFTED from shadowd/main.m — mirror the change in tests/shadowd/RecoveryHarness.m"
diff /tmp/recovery-orig-body.txt /tmp/recovery-copy-body.txt | head -30
exit 1
