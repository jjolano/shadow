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

case ${1-} in
    '') selftest_drift=false ;;
    --selftest-drift) selftest_drift=true ;;
    *) echo 'usage: tests/verify-hook-matrix.sh [--selftest-drift]' >&2; exit 2 ;;
esac

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

if [ "$selftest_drift" = true ]; then
    # Exercise the normal stale-entry path; this name cannot occur in a hook.
    printf '%s\n' '__shadow_matrix_selftest_drift__|libc' >>"$entries"
fi

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

detector=$(sed -n '/^void shdw_detector_detected/,/^}$/p' ShadowCore.dylib/shadowcore.x)
if printf '%s\n' "$detector" | grep -Eq 'NSUserDefaults|NSLog|time\(|NSDate|writeToFile|fopen|open\('; then
    echo 'DETECTOR DRIFT: detector escalation performs logging or persistence I/O'
    rc=1
fi

if grep -Eq 'shdw_record_detector_event|DetectorLog' ShadowCore.dylib/shadowcore.x; then
    echo 'DETECTOR DRIFT: persistent detector telemetry returned'
    rc=1
fi

# dyld's public add/remove callback API has no fixed registration limit.  The
# private ObjC-notifier arrays are intentionally out of scope here, so inspect
# only the two public replacement functions rather than banning their shared
# private-slot constant from the whole source file.
dyld_source=ShadowCore.dylib/hooks/Runtime/dyld.x
dyld_add=$(sed -n '/^static void replaced_dyld_register_func_for_add_image/,/^}/p' "$dyld_source")
dyld_remove=$(sed -n '/^static void replaced_dyld_register_func_for_remove_image/,/^}/p' "$dyld_source")
if printf '%s\n%s\n' "$dyld_add" "$dyld_remove" | grep -Eq 'SHADOW_MAX_OBJC_NOTIFY_CBS|slots full|registrations dropped'; then
    echo 'DYLD DRIFT: public image callback registrations are capped or dropped'
    rc=1
fi

dyld_probe=tools/dyldprobe/main.m
if ! grep -q 'PROBE_DYLD_CALLBACK_COUNT = 9' "$dyld_probe"; then
    echo 'DYLD DRIFT: dyldprobe no longer registers nine distinct callbacks'
    rc=1
fi
for field in expected_existing_images existing_image_replay later_add later_remove concurrency address_uuid; do
    if ! grep -q "$field" "$dyld_probe"; then
        echo "DYLD DRIFT: dyldprobe report omits $field"
        rc=1
    fi
done

# JSON is the dyldprobe evidence contract.  Keep the UI to supplemental
# diagnostics and ensure it cannot rewrite the machine report on refresh.
machine_writes=$(grep -c 'probe_write_machine_report(' "$dyld_probe")
if [ "$machine_writes" -ne 2 ]; then
    echo 'DYLD DRIFT: machine evidence is not single-write'
    rc=1
fi
delegate=$(sed -n '/@implementation AppDelegate/,/@end/p' "$dyld_probe")
if printf '%s\n' "$delegate" | grep -q 'probe_write_machine_report('; then
    echo 'DYLD DRIFT: UI refresh rewrites formal machine evidence'
    rc=1
fi
for section in 1 2 6; do
    if grep -q "probe_section_$section" "$dyld_probe"; then
        echo "DYLD DRIFT: duplicated UI section $section returned"
        rc=1
    fi
done
for section in 3 4 5 7 8 9; do
    if ! grep -q "probe_section_$section" "$dyld_probe"; then
        echo "DYLD DRIFT: retained supplemental UI section $section missing"
        rc=1
    fi
done
if ! grep -q 'Formal JSON evidence is written once at launch' "$dyld_probe"; then
    echo 'DYLD DRIFT: UI no longer identifies JSON as formal evidence'
    rc=1
fi

if grep -q SHADOW_LEGACY_COORDINATOR ShadowCore.dylib/shadowcore.x; then
    echo 'COORDINATOR DRIFT: rollback install path returned'
    exit 1
fi

ctor=$(sed -n '/^%ctor {/,/^%dtor {/p' ShadowCore.dylib/shadowcore.x)
if ! printf '%s\n' "$ctor" | grep -q shdw_coordinator_ctor ||
   printf '%s\n' "$ctor" | grep -Eq 'shadowhook_(dyld|libc|objc)\('; then
    echo 'COORDINATOR DRIFT: ctor no longer installs exclusively through the coordinator'
    exit 1
fi

if grep -q 'outOldPtr:&' ShadowCore.dylib/hooks/Environment/DeviceCheckHooks.m; then
    echo 'BATCHING RISK: DeviceCheck queues an original write to stack storage'
    exit 1
fi

for legacy_pointer_probe in UBReportMetadataDevice EnrollParameters; do
    if ! grep "$legacy_pointer_probe" ShadowCore.dylib/hooks/Environment/DeviceCheckHooks.m | grep -q "'\^'"; then
        echo "DEVICECHECK DRIFT: 3.7.6 pointer hook missing for $legacy_pointer_probe"
        exit 1
    fi
done
if ! grep -q 'shdw_dch_imp0_ptr_null' ShadowCore.dylib/hooks/Environment/DeviceCheckHooks.m; then
    echo 'DEVICECHECK DRIFT: pointer-return hooks lack a typed NULL replacement'
    exit 1
fi
if ! grep -q 'DCHTargetFreeRASP' ShadowCore.dylib/hooks/Environment/DeviceCheck.x ||
   ! grep -q '\$s13TalsecRuntime0A0C5start6configyAA0A6ConfigV_tFZ' ShadowCore.dylib/hooks/Environment/DeviceCheck.x ||
   ! grep -q 'hookRebindSymbol:kSHDWFreeRASPStartSymbol' ShadowCore.dylib/hooks/Environment/DeviceCheck.x ||
   ! grep -q 'HK_SYMBOL_NAME_SWIFT_MANGLED' ShadowCore.dylib/SHDWHookSession.m; then
    echo 'DEVICECHECK DRIFT: freeRASP start disablement is incomplete'
    exit 1
fi

if ! grep -q 'hasPrefix:@"me.jjolano.shadow.test\."' Shadow.dylib/dylib.x; then
    echo 'LOADER DRIFT: detector test bundle namespace lost its verification exemption'
    exit 1
fi
if ! grep -q 'hookRebindSymbol:@"fopen"' ShadowCore.dylib/hooks/FileHiding/libc.x; then
    echo 'LIBC DRIFT: fopen lost its safe rebind path'
    exit 1
fi
if ! grep -q 'strcmp(name, "fork") != 0 || !resolved_fork' ShadowCore.dylib/hooks/FileHiding/sandbox.x; then
    echo 'SANDBOX DRIFT: dynamically resolved fork lost its safe fallback'
    exit 1
fi
if ! grep -q 'hookRebindSymbol:@"dlsym"' ShadowCore.dylib/hooks/Runtime/dyld.x; then
    echo 'DYLD DRIFT: dlsym lost its safe rebind fallback'
    exit 1
fi
if grep -q 'snapshot->entry\[i\]\.name = \[dylib\[@"name"\] fileSystemRepresentation\]' ShadowCore.dylib/hooks/Runtime/dyld.x; then
    echo 'DYLD DRIFT: persistent image snapshot stores an autorelease-scoped path pointer'
    exit 1
fi

# The device matrix must expose the complete landed ledger by canonical ID.
# Keep this source-level check beside the hook matrix so a new/renamed row
# cannot silently turn REL-02 back into an aggregate-only result.
canonical_actual=$(sed -n '/static const CanonicalRegression kCanonicalRegressions\[\] = {/,/^};/p' tools/hookprobe/main.m |
    awk -F'"' '/^[[:space:]]*\{ "/ { print $2 }' | sort)
canonical_expected=$(printf '%s\n' \
    C-01 C-02 C-03 C-04 C-05 C-06 C-07 C-08 C-09 C-10 C-11 C-12 C-13 C-14 C-15 C-16 C-17 \
    CORE-01 CORE-02 CORE-03 CORE-04 CORE-05 CORE-06 CORE-07 CORE-08 CORE-09 \
    DY-01 DY-02 DY-03 DY-04 DY-05 DY-06 DY-07 DY-08 DY-09 DY-10 DY-11 DY-12 \
    FILE-01 FILE-02 FILE-03 FILE-04 FILE-05 FILE-06 FILE-07 FILE-08 FILE-09 FILE-10 \
    N-01 N-02 N-03 N-04 N-05 N-06 N-07 N-08 N-09 N-10 | sort)

if [ "$canonical_actual" != "$canonical_expected" ]; then
    echo 'HOOKPROBE REGRESSION DRIFT: canonical witness IDs differ'
    rc=1
fi

exit $rc
