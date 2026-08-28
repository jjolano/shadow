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
if ! grep -q '@executable_path/shdwtestlib.dylib' "$dyld_probe"; then
    echo 'DYLD DRIFT: bundled stress library is not loaded from dyldprobe'
    rc=1
fi
if [ "$(grep -c 'shdw_path_is_in_main_bundle' ShadowCore.dylib/hooks/Runtime/dyld.x)" -lt 5 ]; then
    echo 'DYLD DRIFT: dyld surfaces no longer share the caller app bundle exemption'
    rc=1
fi
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
if grep -Rqs 'shdw_freerasp_start_disabled\|kSHDWFreeRASPStartSymbol' ShadowCore.dylib/hooks ||
   grep -q '0x57898' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q '"talsecStartReturned": talsecStartReturned' DetectorRunners/FreeRASP/AppDelegate.swift ||
   ! grep -q '"talsecImageLoaded": talsecImageBase() != nil' DetectorRunners/FreeRASP/AppDelegate.swift ||
   ! grep -q '"talsecAllChecksFinished": ThreatStore.shared.finished()' DetectorRunners/FreeRASP/AppDelegate.swift ||
   ! grep -q 'SHDW_SVC_OPCODE_MASK 0xFFE0001FU' ShadowCore.dylib/hooks/FileHiding/svc_patch.x ||
   ! grep -q 'mov x0, #2' ShadowCore.dylib/hooks/FileHiding/svc_patch.x ||
   ! grep -q 'target - (int64_t)site' ShadowCore.dylib/hooks/FileHiding/svc_patch.x ||
   ! grep -q '\[NSBundle mainBundle\]\.bundlePath' ShadowCore.dylib/hooks/FileHiding/svc_patch.x ||
   ! grep -q '/procursus/Applications/' ShadowCore.dylib/hooks/FileHiding/svc_patch.x ||
   ! grep -q 'prefs\[SHDWHookIDSyscall\] = @YES' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q 'shdw_detector_c_write_path_denied(pathname)' ShadowCore.dylib/hooks/FileHiding/libc_lowlevel.x ||
   ! grep -q 'shdw_detector_c_write_path_denied(new)' ShadowCore.dylib/hooks/FileHiding/libc.x ||
   ! grep -q 'shdw_detector_write_path_denied(path)' ShadowCore.dylib/hooks/FileHiding/NSString.x ||
   ! grep -q 'shdw_detector_write_policy_set_enabled(YES)' ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'shadowhook_FreeRASP_shouldHideExistencePath(path)' ShadowCore.dylib/hooks/FileHiding/NSFileManager.x ||
   ! grep -q '@"/.file"' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q '@"/usr/sbin/cfprefsd"' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q 'msg->msgh_bits == 0x1513' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q '0x444f50414d494e45ULL' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q 'shdw_freeRASP_isVersion712' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q '0x4c90' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q 'expectedPrologue' ShadowCore.dylib/hooks/Detectors/FreeRASP.x ||
   ! grep -q 'port == 2222' ShadowCore.dylib/hooks/FileHiding/sandbox.x ||
   ! grep -q 'shadowhook_FreeRASP_preparePreferences' ShadowCore.dylib/shadowcore.x; then
    echo 'DEVICECHECK DRIFT: freeRASP must execute its real start entrypoint'
    exit 1
fi
if grep -Eq 'test_sbiw|\.jbroot' ShadowCore.dylib/hooks/Detectors/FreeRASP.x; then
    echo 'DETECTOR DRIFT: freeRASP write signatures escaped the universal sandbox policy'
    exit 1
fi
if ! grep -q '\[shdw_coordinator_instance prearmDetector\]' ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'stockMarkerVisibleBeforeStart' DetectorRunners/FreeRASP/AppDelegate.swift; then
    echo 'DETECTOR DRIFT: configured detector coverage is not active before SDK startup'
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
if ! grep -q 'SHADW_HOOK_GROUP_IOS_SECURITY_SUITE' ShadowCore.dylib/hooks/FileHiding/libc.x ||
   ! grep -q 'shadowhook_libc_iossecuritysuite' ShadowCore.dylib/hooks/Detectors/IOSSecuritySuite.x ||
   ! grep -q 'shadowhook_NSFileManagerSymbolicLinks' ShadowCore.dylib/hooks/Detectors/IOSSecuritySuite.x ||
   ! grep -q 'shadowhook_LSApplicationWorkspaceCanOpenURL' ShadowCore.dylib/hooks/Detectors/IOSSecuritySuite.x ||
   grep -q 'shadowhook_ImportSlotProtection\|method_getImplementation' ShadowCore.dylib/hooks/Detectors/IOSSecuritySuite.x ||
   ! grep -q 'shadowhook_ImportSlotProtection' ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'shadowhook_objc_methodimpl_detector' ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'SHDWRangeOverlapsProtectedImportSlots' ShadowCore.dylib/hooks/Runtime/ImportSlotProtection.x ||
   ! grep -q 'HK_ARTIFACT_IMPORT_SLOT' ShadowCore.dylib/SHDWHookSession.m ||
   grep -q 'strcmp(d->symbol, "readlink")' ShadowCore.dylib/hooks/FileHiding/libc.x ||
   ! grep -q 'effectivePrefs\[SHDWHookIDFilesystem\] = @NO' ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'effectivePrefs\[SHDWHookIDURLScheme\] = @NO' ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'isApplicationAvailableToOpenURL:(NSURL \*)url error:' ShadowCore.dylib/hooks/Environment/AppEnvironment.x ||
   ! grep -q 'VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY' ShadowCore.dylib/hooks/Runtime/ImportSlotProtection.x; then
    echo 'LIBC DRIFT: IOSSecuritySuite lost its targeted safe filesystem subset'
    exit 1
fi
if ! grep -q 'strcmp(name, "fork") != 0 || !resolved_fork' ShadowCore.dylib/hooks/FileHiding/sandbox.x; then
    echo 'SANDBOX DRIFT: dynamically resolved fork lost its safe fallback'
    exit 1
fi
if [ "$(grep -c 'if(pid) \*pid = -1;' ShadowCore.dylib/hooks/FileHiding/sandbox.x)" -ne 2 ] ||
   [ "$(grep -c '? ENOENT : EPERM;' ShadowCore.dylib/hooks/FileHiding/sandbox.x)" -ne 2 ]; then
    echo 'SANDBOX DRIFT: external posix_spawn lost its stock denial contract'
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
