#!/bin/sh
# Verifies the hook→engine coverage matrix embedded below (moved here from
# tests/coverage-report.sh when the engine-linked coverage harness went
# private) against the ACTUAL engine call sites in
# src/ShadowCore.dylib/hooks/*.x. Same two drift directions + the structural
# checks below them.
#
# The full engine coverage report (per-method gcov %) lives in the private
# harness repo; this file keeps only the drift matrix + structural checks.
#
# Run from the repo root (sh tests/verify-hook-matrix.sh) or via
# make -C tests hook-matrix — ROOT pins every path below.
set -e

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"


case ${1-} in
'') selftest_drift=false ;;
--selftest-drift) selftest_drift=true ;;
*)
 echo 'usage: tests/verify-hook-matrix.sh [--selftest-drift]' >&2
 exit 2
 ;;
esac

MATRIX=tests/verify-hook-matrix.sh
HOOKDIR=src/ShadowCore.dylib/hooks
rc=0

# Reformat tolerance for the source-text pins below: clang-format may respace
# `if(x)` into `if (x)`, rewrap lines, or move a brace onto its own line, so a
# pin compares TOKENS — the snippet and the needle both with every whitespace
# character removed — instead of raw text. Spacing-only changes cannot break a
# pin; a genuinely missing or reordered token still fails it.
norm() { tr -d '[:space:]'; }

# True when the whitespace-stripped "$1" contains each remaining needle, in
# order, with all whitespace likewise stripped. Needles are literal substrings
# (no glob interpretation), so pins carrying `[`, `*` or `?` keep meaning them.
has_tokens() {
 text=$(printf '%s' "$1" | norm)
 shift
 for needle in "$@"; do
  needle=$(printf '%s' "$needle" | norm)
  rest=${text#*"$needle"}
  [ "$rest" != "$text" ] || return 1
  text=$rest
 done
 return 0
}

# Same, for a pin that reads a file rather than an extracted snippet.
file_has_tokens() {
 file=$1
 shift
 [ -f "$file" ] || return 1
 has_tokens "$(cat "$file")" "$@"
}
entries=$(mktemp)
trap 'rm -f "$entries"' 0 HUP INT TERM

# Coverage matrix (hook-facing entry points only; was parsed out of
# coverage-report.sh's report() lines — same `pattern|"groups"` shape).
# ponytail: keep this list in sync with the hook call sites, nothing else.
matrix_entries() {
 cat <<'EOF'
isCPathRestricted|libc libc_lowlevel libc_antidebugging dyld sandbox syscall AppEnvironment svc_patch
isMountPathRestricted|libc
isPathRestricted:options:|libc libc_lowlevel dyld sandbox syscall NSFileManager NSString NSData NSArray NSDictionary NSFileHandle NSBundle NSProcessInfo
isURLRestricted:options:|NSFileManager NSURL NSString NSData NSArray NSDictionary NSFileHandle NSFileVersion NSFileWrapper NSBundle
isSchemeRestricted|LSApplicationWorkspace
isBundleIDRestricted|LSApplicationWorkspace
isProtectedImagePath|dyld objc NSBundle ThreadImage
isAddrRestricted|dyld objc mem sandbox NSThread NSBundle
evaluatePathRestriction|internal
filterPathArray|NSFileManager
fileNoSuchFileErrorForPath:|NSFileManager NSURL NSArray NSData NSDictionary NSFileHandle NSFileVersion NSFileWrapper NSBundle
getStandardizedPath|internal
writeDpkgRuleset|internal
isPathRestrictedQuery|internal
isSchemeRestricted|internal
isBundleIDRestricted|internal
checkForChanges|internal
isPathCompliant|internal
isPathWhitelisted|internal
isPathBlacklisted|internal
compileRulesetAtURL|internal
EOF
}

matrix_entries >"$entries"

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

  # Comment-only mentions (rationale text, no call) don't count —
  # strip // and /* */ comments before matching.
  code=$(sed -e 's|//.*||' -e 's|/\*.*\*/||g' "$f")
  if printf '%s\n' "$code" | grep -q "$pattern" && ! echo " $groups " | grep -q " $base "; then
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

if [ "$(grep -c 'shdw_path_is_in_main_bundle' src/ShadowCore.dylib/hooks/Universal/dyld.x)" -lt 5 ]; then
 echo 'DYLD DRIFT: dyld surfaces no longer share the caller app bundle exemption'
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

# Constructor replay must finish an observed UIKit event synchronously;
# the actual image callback must remain asynchronous.
coordinator_ctor=$(sed -n '/^static void shdw_coordinator_ctor(/,/^}/p' src/ShadowCore.dylib/shadowcore.x)
image_callback=$(sed -n '/^static void shdw_early_image_add(/,/^}/p' src/ShadowCore.dylib/shadowcore.x)
if ! has_tokens "$coordinator_ctor" \
 'installEvent:SHDWEventCtor]' 'if(watcherEnabled)' \
 'shdw_early_image_add(_dyld_get_image_header(i)' \
 'if(__atomic_load_n(&_shdw_uikit_installed, __ATOMIC_ACQUIRE)) {' \
 '[shdw_coordinator_instance installEvent:SHDWEventUIKitLoaded];' \
 'NSLog(@"completed hooks")'; then
 echo 'COORDINATOR DRIFT: observed UIKit replay must finish before ctor returns'
 exit 1
fi
if has_tokens "$image_callback" 'installEvent:'; then
 echo 'COORDINATOR DRIFT: image callback must not install synchronously'
 exit 1
fi
if ! has_tokens "$image_callback" \
 'containsString:@"uikit.framework"' \
 '__atomic_exchange_n(&_shdw_uikit_installed, YES' \
 'enqueueEvent:SHDWEventUIKitLoaded]'; then
 echo 'COORDINATOR DRIFT: UIKit notification lost its image gate or async event'
 exit 1
fi

if ! has_tokens "$ctor" \
 'shdw_adapter_devicecheck_configure(prefs);' \
 'prefs = shdw_adapter_resolve_preferences(prefs);'; then
 echo 'ADAPTER DRIFT: authorization must be captured before presence resolution'
 rc=1
fi
if [ "$(printf '%s\n' "$ctor" | grep -c 'shdw_adapter_devicecheck_configure(prefs);')" -ne 1 ]; then
 echo 'ADAPTER DRIFT: authorization must not be overwritten after resolution'
 rc=1
fi
devicecheck_install=$(sed -n '/^NSUInteger shdw_devicecheck_install_hooks(/,/^}/p' src/ShadowCore.dylib/hooks/Adapters/DeviceCheckHooks.m)
if ! has_tokens "$devicecheck_install" \
 'if(target != DCHTargetNone && !(enabledTargets & target))' 'continue;' \
 'performWhenTargetAvailable:' \
 'if(target != DCHTargetNone && !shdw_devicecheck_target_available(target)) return NO;' \
 'objc_getClass(desc->className)' 'hookMessageInClass:dispatchClass'; then
 echo 'ADAPTER DRIFT: authorized rows must use shared readiness before attempting'
 rc=1
fi
autodetect=src/ShadowCore.dylib/hooks/Adapters/DetectorAutoDetect.x
availability=$(sed -n '/^BOOL shdw_devicecheck_target_available(/,/^}/p' "$autodetect")
if ! has_tokens "$availability" \
 'case DCHTargetDTT: return shdw_detect_dtt();' \
 'case DCHTargetSafeDevice: return shdw_detect_safedevice();' \
 'case DCHTargetJailMonkey: return shdw_detect_jailmonkey();'; then
 echo 'ADAPTER DRIFT: readiness must reuse existing fingerprints'
 rc=1
fi
if ! sed -n '/^static BOOL shdw_detect_safedevice(void) {/,/^}/p' "$autodetect" | grep -q 'return matches >= 2;'; then
 echo 'ADAPTER DRIFT: partial readiness threshold changed'
 rc=1
fi

# LocalAuthentication is not linked by ShadowCore and can load after the UIKit
# event this unit installs on. Probing once would drop the hook for the whole
# process; the install must be queued for the session's pending-target retry.
passcode=$(sed -n '/^void shdw_universal_passcode_status(/,/^}/p' src/ShadowCore.dylib/hooks/Universal/AppEnvironment.x)
if ! has_tokens "$passcode" 'performWhenTargetAvailable:' 'objc_getClass("LAContext")' \
 'return NO;' '%init(shadowhook_LAContext)'; then
 echo 'PASSCODE DRIFT: LAContext install must defer until the class loads'
 rc=1
fi

if grep -q 'outOldPtr:&' src/ShadowCore.dylib/hooks/Adapters/DeviceCheckHooks.m; then
 echo 'BATCHING RISK: DeviceCheck queues an original write to stack storage'
 exit 1
fi

# Journaled rebind cells must be process-lifetime: replay dereferences them
# on later image loads. Bare address-of locals are stack storage.
if grep -rn -- 'hookRebindSymbol.*outOldPtr:&[A-Za-z_]' src/ShadowCore.dylib/ | grep -qv -- 'outOldPtr:(void'; then
 echo 'BATCHING RISK: journaled rebind cell is not a global'
 rc=1
fi

# A failed attempt must neutralize caller input without erasing a continuation
# this session published (a live replacement may chain through it).
apply_once=$(sed -n '/^static BOOL shdw_apply_hook_spec_once(/,/^}/p' src/ShadowCore.dylib/SHDWHookSession.m)
if ! has_tokens "$apply_once" \
 'BOOL entryLive = shdw_cell_holds_live_original(oldPtr);' 'if(oldPtr && !entryLive) {'; then
 echo 'SESSION DRIFT: setup-failure paths must snapshot then neutralize unpublished cells'
 rc=1
fi
finish_helper=$(sed -n '/^static void shdw_finish_uninstalled_hook(/,/^}/p' src/ShadowCore.dylib/SHDWHookSession.m)
if ! has_tokens "$finish_helper" 'result.mutation == HK_MUTATION_NONE && !entryLive'; then
 echo 'SESSION DRIFT: clean failures must preserve earlier-attempt continuations'
 rc=1
fi
if ! grep -q 'shdw_note_published_cell(oldPtr);' src/ShadowCore.dylib/SHDWHookSession.m; then
 echo 'SESSION DRIFT: published continuations are not tracked'
 rc=1
fi
# Every raw cell clear must sit under an entryPublished guard: only a
# continuation from an earlier attempt may survive a failure.
for line in $(grep -n '\*oldPtr[[:space:]]*=[[:space:]]*NULL;' src/ShadowCore.dylib/SHDWHookSession.m | cut -d: -f1); do
 if [ "$line" -gt 3 ]; then
  start=$((line - 3))
 else
  start=1
 fi
 if ! sed -n "${start},$((line - 1))p" src/ShadowCore.dylib/SHDWHookSession.m | grep -q 'entryLive'; then
  echo "SESSION DRIFT: unguarded cell clear at SHDWHookSession.m:$line"
  rc=1
 fi
done

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
 ! grep -q 'bl _shdw_svc_should_deny' src/ShadowCore.dylib/hooks/Universal/svc_patch.x ||
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
if ! grep -q 'SHDWUniversalHarnessBaselineID] = @YES' src/ShadowCore.dylib/shadowcore.x ||
 ! grep -q 'hasActiveDetectorAdapter || harnessPrearmed || embeddedDetectors || forcedPrearm' src/ShadowCore.dylib/shadowcore.x ||
 ! grep -q 'hasPrefix:@"me.jjolano.shadow.test\."' src/ShadowCore.dylib/shadowcore.x ||
 ! file_has_tokens src/Shadow.framework/HookConfiguration.m 'prefs[SHDWUniversalHarnessBaselineID] != nil' ||
 ! grep -q '_harnessProfile' src/ShadowCore.dylib/HookCoordinator.m ||
 ! file_has_tokens src/Shadow.framework/Settings.m 'app_settings = fileAppSettings' ||
 ! grep -q 'filePreferences)' src/Shadow.framework/Settings.m ||
 ! file_has_tokens src/Shadow.framework/Settings.m 'result[SHDWUniversalHarnessBaselineID] = baseline'; then
 echo 'HARNESS PREARM DRIFT: explicit prearmed mode must activate detector coverage'
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
# The private harness build script runs from its own checkout, but builds the
# public sources supplied through SHADOW_SRC.
if ! file_has_tokens src/Shadow.framework/HookConfiguration.m 'SHDWUniversalSyscallID : @(YES)'; then
 echo 'HOOK CONFIG DRIFT: the universal syscall feature must stay enabled'
 exit 1
fi
if ! grep -q 'hookRebindSymbol:@"fopen"' src/ShadowCore.dylib/hooks/Universal/libc.x; then
 echo 'LIBC DRIFT: fopen lost its safe rebind path'
 exit 1
fi
getppid_rebind=$(sed -n '/} else if(group == SHADW_HOOK_GROUP_ANTIDEBUG &&/,/} else {/p' src/ShadowCore.dylib/hooks/Universal/libc.x)
if ! printf '%s\n' "$getppid_rebind" | grep -q 'strcmp(d->symbol, "getppid") == 0' ||
 ! printf '%s\n' "$getppid_rebind" | grep -q 'hookRebindSymbol:@"getppid"' ||
 ! printf '%s\n' "$getppid_rebind" | grep -q 'outOldPtr:NULL' ||
 printf '%s\n' "$getppid_rebind" | grep -q 'hookFunction:'; then
 echo 'LIBC DRIFT: getppid must use the rebind-only shared-cache path'
 exit 1
fi
if ! has_tokens "$getppid_rebind" '*d->original = target;' 'hookRebindSymbol:@"getppid"'; then
 echo 'LIBC DRIFT: getppid publishes its rebind continuation too late'
 exit 1
fi
if grep -q 'LIBC | METADATA' src/ShadowCore.dylib/hooks/Universal/libc.x; then
 echo 'LIBC DRIFT: IOSSecuritySuite overlap must use one install lane'
 exit 1
fi
# A rebind commit may call the replacement before it returns. Its continuation
# must therefore be written directly to the caller's output cell, not staged
# in a local that is copied out after the mutation.
session_apply=$(sed -n '/^static BOOL shdw_apply_hook_spec(/,/^}/p' src/ShadowCore.dylib/SHDWHookSession.m)
if has_tokens "$session_apply" 'attemptOldPtr' || has_tokens "$session_apply" 'spec, &original,'; then
 echo 'HOOK SESSION DRIFT: continuation output is staged across commit'
 exit 1
fi
if ! has_tokens "$session_apply" 'spec, oldPtr, backendOverride,' 'spec, oldPtr, NULL,'; then
 echo 'HOOK SESSION DRIFT: hook attempts must publish directly to caller storage'
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
 [ "$(grep -c 'shdw_spawn_deny_errno(' src/ShadowCore.dylib/hooks/Universal/sandbox.x)" -lt 2 ] ||
 ! grep -q 'return (path && \[_shadow isCPathRestricted:path\]) ? ENOENT : EPERM;' src/ShadowCore.dylib/hooks/Universal/sandbox.x; then
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
if ! file_has_tokens src/Shadow.framework/Headers/Shadow/JBPath.h 'strncmp(path, "/private/var/jb", 15)' ||
 ! file_has_tokens src/Shadow.framework/JBPath.m 'shdw_is_restricted_root_with_prefix(path, NULL)'; then
 echo 'FREERASP DRIFT: private /var/jb alias is not covered by the shared root predicate'
 rc=1
fi
# PolicyTests.m cases live in the private harness; run there.
if ! grep -q 'SHDWRequestUniversalFeatures' src/ShadowCore.dylib/hooks/Adapters/IOSSecuritySuite.x ||
 ! grep -q 'SHDWAdapterPathIsHidden' src/ShadowCore.dylib/hooks/Universal/NSFileManager.x ||
 ! grep -q 'SHDWRemapDladdrAddress' src/ShadowCore.dylib/hooks/Universal/dyld.x; then
 echo 'BOUNDARY DRIFT: the neutral adapter bridge is incomplete'
 exit 1
fi

# The device matrix must expose the complete landed ledger by canonical ID.
# hookprobe lives in the private harness; public runs skip this section.

exit $rc
