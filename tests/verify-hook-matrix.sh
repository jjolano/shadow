#!/bin/sh
# Verifies the hook→engine coverage matrix embedded in coverage-report.sh
# against the ACTUAL engine call sites in src/ShadowCore.dylib/hooks/*.x.
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
HOOKDIR=src/ShadowCore.dylib/hooks
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

detector=$(sed -n '/^void shdw_detector_detected/,/^}$/p' src/ShadowCore.dylib/shadowcore.x)
if printf '%s\n' "$detector" | grep -Eq 'NSUserDefaults|NSLog|time\(|NSDate|writeToFile|fopen|open\('; then
    echo 'DETECTOR DRIFT: detector escalation performs logging or persistence I/O'
    rc=1
fi

if grep -Eq 'shdw_record_detector_event|DetectorLog' src/ShadowCore.dylib/shadowcore.x; then
    echo 'DETECTOR DRIFT: persistent detector telemetry returned'
    rc=1
fi

# dyld's public add/remove callback API has no fixed registration limit.  The
# private ObjC-notifier arrays are intentionally out of scope here, so inspect
# only the two public replacement functions rather than banning their shared
# private-slot constant from the whole source file.
dyld_source=src/ShadowCore.dylib/hooks/Universal/dyld.x
dyld_add=$(sed -n '/^static void replaced_dyld_register_func_for_add_image/,/^}/p' "$dyld_source")
dyld_remove=$(sed -n '/^static void replaced_dyld_register_func_for_remove_image/,/^}/p' "$dyld_source")
if printf '%s\n%s\n' "$dyld_add" "$dyld_remove" | grep -Eq 'SHADOW_MAX_OBJC_NOTIFY_CBS|slots full|registrations dropped'; then
    echo 'DYLD DRIFT: public image callback registrations are capped or dropped'
    rc=1
fi

dyld_probe=tests/tools/dyldprobe/main.m
if ! grep -q '@executable_path/Frameworks/shdwtestlib.dylib' "$dyld_probe"; then
    echo 'DYLD DRIFT: bundled stress library is not loaded from dyldprobe'
    rc=1
fi
if ! grep -q 'SHDWDyldProbeWriteDashboardReport' tests/ShadowHarness/Detectors.m ||
   ! grep -q 'shdwtestlib.dylib' tests/ShadowHarness/Makefile; then
    echo 'DYLD DRIFT: Harness no longer embeds the dyldprobe runner and stress library'
    rc=1
fi
if grep -q 'shadow-dyldprobe://run' tests/ShadowHarness/DetectorDashboard.m; then
    echo 'DYLD DRIFT: Harness still hands dyldprobe off to a separate app'
    rc=1
fi
if [ "$(grep -c 'shdw_path_is_in_main_bundle' src/ShadowCore.dylib/hooks/Universal/dyld.x)" -lt 5 ]; then
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

if grep -q SHADOW_LEGACY_COORDINATOR src/ShadowCore.dylib/shadowcore.x; then
    echo 'COORDINATOR DRIFT: rollback install path returned'
    exit 1
fi

ctor=$(sed -n '/^%ctor {/,/^%dtor {/p' src/ShadowCore.dylib/shadowcore.x)
if ! printf '%s\n' "$ctor" | grep -q shdw_coordinator_ctor ||
   printf '%s\n' "$ctor" | grep -Eq 'shadowhook_(dyld|libc|objc)\('; then
    echo 'COORDINATOR DRIFT: ctor no longer installs exclusively through the coordinator'
    exit 1
fi

if grep -q 'outOldPtr:&' src/ShadowCore.dylib/hooks/Adapters/DeviceCheckHooks.m; then
    echo 'BATCHING RISK: DeviceCheck queues an original write to stack storage'
    exit 1
fi

for legacy_pointer_probe in UBReportMetadataDevice EnrollParameters; do
    if ! grep "$legacy_pointer_probe" src/ShadowCore.dylib/hooks/Adapters/DeviceCheckHooks.m | grep -q "'\^'"; then
        echo "DEVICECHECK DRIFT: 3.7.6 pointer hook missing for $legacy_pointer_probe"
        exit 1
    fi
done
if ! grep -q 'shdw_dch_imp0_ptr_null' src/ShadowCore.dylib/hooks/Adapters/DeviceCheckHooks.m; then
    echo 'DEVICECHECK DRIFT: pointer-return hooks lack a typed NULL replacement'
    exit 1
fi
if grep -Rqs 'shdw_freerasp_start_disabled\|kSHDWFreeRASPStartSymbol' src/ShadowCore.dylib/hooks ||
   grep -q '0x57898' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q 'SHDW_SVC_OPCODE_MASK 0xFFE0001FU' src/ShadowCore.dylib/hooks/Universal/svc_patch.x ||
   ! grep -q 'mov x0, #2' src/ShadowCore.dylib/hooks/Universal/svc_patch.x ||
   ! grep -q 'target - (int64_t)site' src/ShadowCore.dylib/hooks/Universal/svc_patch.x ||
   ! grep -q '\[NSBundle mainBundle\]\.bundlePath' src/ShadowCore.dylib/hooks/Universal/svc_patch.x ||
   ! grep -q '/procursus/Applications/' src/ShadowCore.dylib/hooks/Universal/svc_patch.x ||
   ! grep -q 'prefs\[SHDWUniversalSyscallID\] = @YES' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q 'shdw_detector_c_write_path_denied(pathname)' src/ShadowCore.dylib/hooks/Universal/libc_lowlevel.x ||
   ! grep -q 'shdw_detector_c_write_path_denied(new)' src/ShadowCore.dylib/hooks/Universal/libc.x ||
   ! grep -q 'shdw_detector_write_path_denied(path)' src/ShadowCore.dylib/hooks/Universal/NSString.x ||
   ! grep -q 'shdw_detector_write_policy_set_enabled(YES)' src/ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'SHDWAdapterPathIsHidden(path)' src/ShadowCore.dylib/hooks/Universal/NSFileManager.x ||
   ! grep -q '@"/.file"' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q '@"/usr/sbin/cfprefsd"' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q 'msg->msgh_bits == 0x1513' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q '0x444f50414d494e45ULL' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q 'shdw_freeRASP_versionForHeader' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q '0x4c90' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q 'Prologue' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x ||
   ! grep -q 'port == 2222' src/ShadowCore.dylib/hooks/Universal/sandbox.x ||
   ! grep -q 'shdw_adapter_freerasp_prepare_preferences' src/ShadowCore.dylib/shadowcore.x; then
    echo 'DEVICECHECK DRIFT: freeRASP must execute its real start entrypoint'
    exit 1
fi
if grep -Eq 'test_sbiw|\.jbroot' src/ShadowCore.dylib/hooks/Adapters/FreeRASP.x; then
    echo 'DETECTOR DRIFT: freeRASP write signatures escaped the universal sandbox policy'
    exit 1
fi
if ! grep -q '\[shdw_coordinator_instance prearmDetector\]' src/ShadowCore.dylib/shadowcore.x; then
    echo 'DETECTOR DRIFT: configured detector coverage is not active before SDK startup'
    exit 1
fi

if ! grep -q 'hasPrefix:@"me.jjolano.shadow.test\."' src/Shadow.dylib/dylib.x; then
    echo 'LOADER DRIFT: detector test bundle namespace lost its verification exemption'
    exit 1
fi
if ! grep -q 'if(!buf && bufsize == 0)' src/ShadowCore.dylib/hooks/Universal/libc.x ||
   [ "$(grep -c 'int rawCount = original_getfsstat(NULL, 0, flags);' src/ShadowCore.dylib/hooks/Universal/libc.x)" -lt 2 ] ||
   ! grep -q 'shdw_getfsstat_filtered_snapshot(flags, rawCount, buf, capacity)' src/ShadowCore.dylib/hooks/Universal/libc.x; then
    echo 'MOUNT DRIFT: getfsstat buffers must be populated from a full raw snapshot'
    exit 1
fi
if grep -q 'SHDWRunAllDetectors' tests/ShadowHarness/SceneDelegate.m; then
    echo 'HARNESS LIFECYCLE DRIFT: full detector suite must not run during scene creation'
    exit 1
fi
if ! grep -q -- '--shadow-headless-run-all' tests/ShadowHarness/main.m; then
    echo 'HARNESS HEADLESS DRIFT: Run All needs a direct executable test mode'
    exit 1
fi
if ! grep -q 'SHDWUniversalHarnessBaselineID] == nil' src/ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'hasActiveDetectorAdapter || harnessPrearmed || forcedPrearm' src/ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'hasPrefix:@"me.jjolano.shadow.test\."' src/ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'prefs\[SHDWUniversalHarnessBaselineID\] != nil' src/Shadow.framework/HookConfiguration.m ||
   ! grep -q '_harnessProfile' src/ShadowCore.dylib/HookCoordinator.m ||
   ! grep -q 'app_settings = fileAppSettings' src/Shadow.framework/Settings.m ||
   ! grep -q 'filePreferences)' src/Shadow.framework/Settings.m ||
   ! grep -q 'result\[SHDWUniversalHarnessBaselineID\] = baseline' src/Shadow.framework/Settings.m; then
    echo 'HARNESS PREARM DRIFT: explicit prearmed mode must activate detector coverage'
    exit 1
fi
if ! grep -q 'sdk_fallback_inventory' tests/ShadowHarness/Battery.m ||
   ! grep -q 'sdk_fallback_observed' tests/ShadowHarness/Battery.m ||
   ! grep -q 'Run All SDK fallback activation missing' tests/stealth_device.py; then
    echo 'HARNESS FALLBACK DRIFT: Run All must prove deferred SDK adapter activation'
    exit 1
fi
if ! grep -q 'probe_launch_context(probe_documents_directory())' tests/tools/dyldprobe/main.m ||
   ! grep -q 'return @"/var/mobile/Documents"' tests/tools/dyldprobe/main.m; then
    echo 'DYLD DRIFT: embedded probe must inherit the Harness launch mode'
    exit 1
fi
if grep -q 'hasPrefix:@"/var/mobile"' src/ShadowCore.dylib/hooks/hooks.h ||
   grep -q 'strncmp(path, "/var/mobile"' src/ShadowCore.dylib/hooks/hooks.h; then
    echo 'PATH DRIFT: /var/mobile cannot bypass jailbreak path policy'
    exit 1
fi
if grep -q 'stringByStandardizingPath __attribute__' src/ShadowCore.dylib/hooks/Universal/NSString.x ||
   grep -q 'URLByStandardizingPath __attribute__' src/ShadowCore.dylib/hooks/Universal/NSURL.x; then
    echo 'PATH DRIFT: lexical path normalization must not be pass-through swizzled'
    exit 1
fi
if ! grep -q 'SHDWRequestUniversalFeatures' src/ShadowCore.dylib/hooks/Adapters/IOSSecuritySuite.x ||
   grep -q 'shdw_universal_' src/ShadowCore.dylib/hooks/Adapters/IOSSecuritySuite.x ||
   ! grep -q 'hookRebindSymbol:@"dlsym"' src/ShadowCore.dylib/hooks/Universal/dyld.x ||
   ! grep -q 'resolved_getppid = dlsym' src/ShadowCore.dylib/hooks/Universal/libc_antidebugging.x ||
   ! grep -q 'HK_IMAGE_EXACT_HEADER' src/ShadowCore.dylib/SHDWHookSession.m ||
   grep -q 'HK_REACH_EXACT_IMAGE_SCOPE' src/ShadowCore.dylib/SHDWHookSession.m; then
    echo 'HARNESS FALLBACK DRIFT: late-loaded detector imports must be rebound in their exact image'
    exit 1
fi
if ! grep -q 'statfs("/var/jb"' tests/tools/dyldprobe/main.m ||
   grep -q 'stat("/var/jb"' tests/tools/dyldprobe/main.m; then
    echo 'DYLD DRIFT: injection canary must use a universally installed filesystem hook'
    exit 1
fi
if ! grep -q 'DeviceSecurityKitRunner' tests/DetectorRunners/DeviceSecurityKit/Makefile ||
   ! grep -q 'devicesecuritykit' tests/DetectorRunners/DeviceSecurityKit/AppDelegate.swift; then
    echo 'HARNESS DSK DRIFT: DeviceSecurityKit must execute in its isolated runner'
    exit 1
fi
if grep -q 'SecurityLoggerManager\|prepareForHarness' tests/ShadowHarness/Detectors.m; then
    echo 'HARNESS DSK DRIFT: isolated DeviceSecurityKit logger leaked into the Harness'
    exit 1
fi
if grep -q 'DEBUG-9be1\|shdw_write_run_all_debug_state' tests/ShadowHarness/Detectors.m; then
    echo 'HARNESS DEBUG DRIFT: temporary Run All diagnostics must not ship'
    exit 1
fi
if ! grep -q 'INCLUDE_DETECTOR_RUNNERS' tests/ShadowHarness/Makefile ||
   ! grep -q 'SHDW_DYLDPROBE_OBJ_DIR := ../tools/dyldprobe/.theos/obj$' tests/ShadowHarness/Makefile ||
   ! grep -q 'm -C "$ROOT/tests/tools/dyldprobe" stage FINALPACKAGE=1' scripts/build-detector-harness.sh; then
    echo 'HARNESS PACKAGE DRIFT: final packages must include isolated runners and dyld stress library'
    exit 1
fi
if ! grep -q 'SHDWUniversalSyscallID : @(YES)' src/Shadow.framework/HookConfiguration.m ||
   ! grep -q 'SimulatorDetector.threatDetected()' tests/DetectorRunners/SecurityToolkit/AppDelegate.swift ||
   ! grep -q 'HardwareSecurityDetector.threatDetected()' tests/DetectorRunners/SecurityToolkit/AppDelegate.swift ||
   ! grep -q 'JailbreakDetectionSymbolicLinksCheckService' tests/DetectorRunners/BATJailbreakGuard/AppDelegate.swift ||
   ! grep -q 'JailbreakDetectionChecksumCheckService' tests/DetectorRunners/BATJailbreakGuard/AppDelegate.swift ||
   ! grep -q 'JailbreakDetector.detect()' tests/DetectorRunners/SafetyNet/AppDelegate.swift ||
   ! grep -q 'IntegrityValidator.validateCodeSignature()' tests/DetectorRunners/SafetyNet/AppDelegate.swift ||
   ! grep -q 'ProxyDetector.checkVPNAsProxy()' tests/DetectorRunners/SafetyNet/AppDelegate.swift ||
   ! grep -q 'DSKBridge.isReverseEngineered()' tests/DetectorRunners/DeviceSecurityKit/AppDelegate.swift ||
     ! grep -q 'detect_launchd_deplatformized' tests/DetectorRunners/Roothider/AppDelegate.m ||
     ! grep -q 'JAILMONKEY_DIR)/JailMonkey.m' tests/DetectorRunners/JailMonkey/Makefile ||
     ! grep -q '\[detector canFork\]' tests/DetectorRunners/JailMonkey/AppDelegate.m ||
    ! grep -q 'iossecuritysuite.watchpoint' tests/ShadowHarness/detector-frameworks/bridges/IOSSBridge.swift ||
    ! grep -q 'runnerChecksWithBundleID:' tests/ShadowHarness/detector-frameworks/bridges/IOSSBridge.swift ||
   ! grep -q 'dlopen(framework, RTLD_NOW | RTLD_LOCAL)' tests/DetectorRunners/IOSSecuritySuite/AppDelegate.swift ||
   ! grep -q 'shdwInstallHarnessSDKFallback' tests/DetectorRunners/IOSSecuritySuite/AppDelegate.swift ||
   ! grep -q 'isJb()' tests/DetectorRunners/isJailbroken/AppDelegate.m ||
   ! grep -q 'isInjectedWithDynamicLibrary()' tests/DetectorRunners/isJailbroken/AppDelegate.m ||
   ! grep -q 'isDebugged()' tests/DetectorRunners/isJailbroken/AppDelegate.m ||
   ! grep -q 'ISJB_DIR)/JB.m' tests/DetectorRunners/isJailbroken/Makefile ||
   ! grep -q 'isJailbrokenRunner' tests/DetectorRunners/isJailbroken/Makefile ||
   ! grep -q 'SwiftyJBD.isJailbroken()' tests/DetectorRunners/SwiftyJBD/AppDelegate.swift ||
   ! grep -q 'SWIFTYJBD_DIR)/JailBreak.swift' tests/DetectorRunners/SwiftyJBD/Makefile ||
   ! grep -q 'SwiftyJBDRunner' tests/DetectorRunners/SwiftyJBD/Makefile ||
   ! grep -q 'RoothiderRunner_CODESIGN_FLAGS' tests/DetectorRunners/Roothider/Makefile ||
   ! grep -q 'application-identifier' tests/DetectorRunners/Roothider/Resources/RoothiderRunner.entitlements; then
    echo 'HARNESS OPTION DRIFT: detector runners must execute every supported one-shot check'
    exit 1
fi
if ! grep -q 'ShdwReadEvidenceData' tests/ShadowHarness/DetectorDashboard.m ||
   ! grep -q 'ShdwWriteEvidenceData' tests/ShadowHarness/Detectors.m ||
   ! grep -q 'written = ShdwWriteEvidenceData(data, path);' tests/tools/dyldprobe/main.m; then
    echo 'HARNESS EVIDENCE I/O DRIFT: detector reports must bypass their own file hooks'
    exit 1
fi
if grep -q 'shdw_load_framework\|shdw_dlopen_framework' tests/ShadowHarness/Detectors.m ||
   ! grep -q 'SHDWRunnerForID' tests/ShadowHarness/Detectors.m ||
   ! grep -q 'SHDWStartEmbeddedDyldProbe' tests/ShadowHarness/Detectors.m; then
    echo 'HARNESS DRIFT: SDKs must run through isolated runners and dyldprobe in-process'
    exit 1
fi
if ! grep -q 'asyncAfter.*30' tests/DetectorRunners/FreeRASP/AppDelegate.swift; then
    echo 'HARNESS DRIFT: FreeRASP must settle before returning its runner report'
    exit 1
fi
if ! grep -q 'hookRebindSymbol:@"fopen"' src/ShadowCore.dylib/hooks/Universal/libc.x; then
    echo 'LIBC DRIFT: fopen lost its safe rebind path'
    exit 1
fi
if grep -q 'LIBC | METADATA' src/ShadowCore.dylib/hooks/Universal/libc.x; then
    echo 'LIBC DRIFT: IOSSecuritySuite overlap must use one install lane'
    exit 1
fi
if ! grep -q 'SHADW_HOOK_GROUP_FEATURE_METADATA' src/ShadowCore.dylib/hooks/Universal/libc.x ||
   ! grep -q 'SHDWRequestUniversalFeatures' src/ShadowCore.dylib/hooks/Adapters/IOSSecuritySuite.x ||
   grep -q 'shdw_universal_' src/ShadowCore.dylib/hooks/Adapters/IOSSecuritySuite.x ||
   ! grep -q 'shdw_universal_import_slot_protection' src/ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'shdw_universal_objc_methodimpl_detector' src/ShadowCore.dylib/shadowcore.x ||
    ! grep -q 'SHDWRangeOverlapsProtectedImportSlots' src/ShadowCore.dylib/hooks/Universal/ImportSlotProtection.x ||
    ! grep -q 'hk_artifact_is_import_slot' src/ShadowCore.dylib/SHDWHookSession.m ||
   grep -q 'strcmp(d->symbol, "readlink")' src/ShadowCore.dylib/hooks/Universal/libc.x ||
    grep -q 'effectivePrefs\[SHDWUniversalFilesystemID\] = @NO' src/ShadowCore.dylib/shadowcore.x ||
    grep -q 'effectivePrefs\[SHDWUniversalURLSchemeID\] = @NO' src/ShadowCore.dylib/shadowcore.x ||
   ! grep -q 'isApplicationAvailableToOpenURL:(NSURL \*)url error:' src/ShadowCore.dylib/hooks/Universal/AppEnvironment.x ||
   ! grep -q 'VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY' src/ShadowCore.dylib/hooks/Universal/ImportSlotProtection.x; then
    echo 'LIBC DRIFT: IOSSecuritySuite lost its targeted safe filesystem subset'
    exit 1
fi
if ! grep -q 'strcmp(name, "fork") != 0 || !resolved_fork' src/ShadowCore.dylib/hooks/Universal/sandbox.x; then
    echo 'SANDBOX DRIFT: dynamically resolved fork lost its safe fallback'
    exit 1
fi
if [ "$(grep -c 'if(pid) \*pid = -1;' src/ShadowCore.dylib/hooks/Universal/sandbox.x)" -ne 2 ] ||
   [ "$(grep -c '? ENOENT : EPERM;' src/ShadowCore.dylib/hooks/Universal/sandbox.x)" -ne 2 ]; then
    echo 'SANDBOX DRIFT: external posix_spawn lost its stock denial contract'
    exit 1
fi
if ! grep -q 'hookRebindSymbol:@"dlsym"' src/ShadowCore.dylib/hooks/Universal/dyld.x; then
    echo 'DYLD DRIFT: dlsym lost its safe rebind fallback'
    exit 1
fi
if grep -q 'snapshot->entry\[i\]\.name = \[dylib\[@"name"\] fileSystemRepresentation\]' src/ShadowCore.dylib/hooks/Universal/dyld.x; then
    echo 'DYLD DRIFT: persistent image snapshot stores an autorelease-scoped path pointer'
    exit 1
fi

if grep -Rqs 'shdw_universal_' src/ShadowCore.dylib/hooks/Adapters ||
   grep -Rqs 'shadowhook_\(dyld\|libc\|NSFileManager\|LSApplicationWorkspace\)' src/ShadowCore.dylib/hooks/Adapters; then
    echo 'BOUNDARY DRIFT: adapter sources directly reference universal installers'
    exit 1
fi
if grep -Rqs 'shdw_adapter_\|FreeRASP\|DeviceSecurityKit\|IOSSecuritySuite\|DeviceCheck' src/ShadowCore.dylib/hooks/Universal; then
    echo 'BOUNDARY DRIFT: universal sources directly reference an adapter'
    exit 1
fi
if ! grep -q 'strncmp(path, "/private/var/jb", 15)' src/Shadow.framework/JBPath.m ||
   ! grep -q 'private var jb alias restricted' tests/PolicyTests.m ||
   ! grep -q 'private var jb prefix boundary allowed' tests/PolicyTests.m; then
    echo 'FREERASP DRIFT: private /var/jb alias is not covered by the shared root predicate'
    rc=1
fi
if ! grep -q 'SHDWRequestUniversalFeatures' src/ShadowCore.dylib/hooks/Adapters/IOSSecuritySuite.x ||
   ! grep -q 'SHDWAdapterPathIsHidden' src/ShadowCore.dylib/hooks/Universal/NSFileManager.x ||
   ! grep -q 'SHDWRemapDladdrAddress' src/ShadowCore.dylib/hooks/Universal/dyld.x; then
    echo 'BOUNDARY DRIFT: the neutral adapter bridge is incomplete'
    exit 1
fi

# The device matrix must expose the complete landed ledger by canonical ID.
# Keep this source-level check beside the hook matrix so a new/renamed row
# cannot silently turn REL-02 back into an aggregate-only result.
canonical_actual=$(sed -n '/static const CanonicalRegression kCanonicalRegressions\[\] = {/,/^};/p' tests/tools/hookprobe/main.m |
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
