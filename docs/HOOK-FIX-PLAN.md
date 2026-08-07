# Shadow Hook Hardening Plan

Adversarial fix plan: every change is justified by an attacker technique it closes.
Triage buckets per finding: **FIX** (real leak, repair), **REMOVE** (dead/wrong/fingerprinting
hook — a wrong or detectable hook is a liability, not a hook), **CONSOLIDATE** (share one
helper instead of per-method duplication).

Guiding principle: *hook at the chokepoints a detector can actually reach. Every remaining
hook must be reachable by a direct detector call, correct under adversarial input, and
indistinguishable from stock behavior.*

Sources: adversarial review of all 25 hook files + layer fix plans (file, dyld/objc, C,
Foundation/UI), reconciled with direct reading of Core.m, Backend.m, dylib.x, Settings.m.

---

## Phase 0 — Shared Core foundations (blocks everything else)

All layers converged on these. Land first; every Wave-1 fix consumes them.

### C0-1. Canonical, operation-aware path classification (`Shadow.framework/Core.m`)

- Resolve symlinks **component-by-component** (including intermediate app-local aliases like
  `@executable_path/.jbroot`), file-reference URLs, and relative paths, before the
  bundle/home exemption applies. Keep final-component no-follow semantics for
  lstat/readlink-style queries. Re-check resolved targets even when the lexical path is
  inside app home/bundle.
- Distinguish **read/existence** vs **write/create/delete** intent (`kShadowRestrictionOp`):
  write classification must not require the target to exist (kills C3 nonexistent-path
  write probes). Add a bounded subtree query ("contains restricted descendant") for
  recursive copy/move/remove/wrapper operations.
- Collapse rootless/rooted aliases (`/jb`, `/var/jb`, preboot roots) to one decision.
- Trim the 2s decision cache TTL (or invalidate on ruleset generation change); it can serve
  a stale "allowed" after a jailbreak file appears.

### C0-2. Effective-origin caller classification (`Core.m:87-101`, `hooks.h:52`)

Replace "any image outside the app bundle is a tweak" with: **only explicit Shadow-internal
operations (TLS-scoped) see truth; everything else — app code, embedded/static detectors,
system frames acting on their behalf (Foundation forwarding, NSInvocation, KVC) — sees
filtered results.** System wrappers acting on behalf of the app must not bypass filtering
(kills C2 fast-enumeration and mediation leaks).

### C0-3. Shared helpers (one per concern, per layer)

| Helper | Consumers | Kills |
|---|---|---|
| Cocoa error factory: `NSCocoaErrorDomain` + correct file code + `NSFilePathErrorKey`/`NSURLErrorKey` userInfo | all Foundation file hooks (C4) | error-domain/userInfo fingerprint |
| Mount-record sanitizer: iterate all entries, remove restricted mounts, compact count, respect bufsize, never mutate libc's table, preserve real snapshot bit, `MNT_RDONLY` only | `statfs/fstatfs/statvfs/fstatvfs/getfsstat/getmntinfo(+_r_np)` | jailbreak/bind-mount enumeration, synthetic-snapshot fingerprint |
| dirfd resolver: absolute paths ignore dirfd; `AT_FDCWD` or `F_GETPATH`; invalid dirfd → original `EBADF`; valid-but-unresolved dir vnode → fail closed; no fd 0–2 exemption | all `*at` hooks (readlinkat, fstatat, faccessat, unlinkat, openat, + P2 `linkat/symlinkat/renameat/mkdirat/utimensat/fchmodat`) | nil-dict crashes, `EBADF` fingerprints, relative bypass, reused-stdio bypass |
| Hidden-app predicate: restricted bundle URL **or** case-insensitive restricted bundle-ID | all `LSApplicationWorkspace` results, openURL, UIApplication | Cydia/Sileo/Zebra/Dopamine/TrollStore proxies, nil-proxy leaks |
| Blocked-task helper: real suspended task via `%orig`, wrapped completion → one async `NSURLErrorFileDoesNotExist`, cancel before I/O, return the task | all NSURLSession URL/request/upload/download/WebSocket overloads | nonnull-contract traps, never-called completions (hangs) |
| Scheme normalization: lowercase both rules and queries | Backend/UIApplication/LSApplicationWorkspace | case-variant scheme probes |
| Protected-name policy: generation-versioned, allocation-free image/class/bundle/asset predicates (exact names, no substring matching) | dyld/objc/NSThread/NSBundle/UIImage filtering | Shadow/HookKit/RootBridge/libSandy class+image discovery |

### C0-4. Gating & backend integrity (`dylib.x`, `Settings.m`)

- **Defaults:** re-evaluate per group. Off-by-default = that vector is 100% exposed on a
  default install. Recommended: enable `Hook_ObjCRuntime`, `Hook_TweakClasses`,
  `Hook_SymLookup`, `Hook_LowLevelC`, `Hook_HideApps` by default (safe groups); keep the
  blanket-denial groups (Sandbox, Memory, Syscall, Mach, AntiDebugging, FakeMac) opt-in
  (they break legitimate apps).
- **Detector escalation:** `shdw_detector_present` must force-enable the safe groups
  (currently it only steers dyld routing). Extend detection beyond 3 hardcoded names:
  reuse the DeviceCheck.x third-party detector-class list (class presence check) +
  curated image-name patterns; re-scan on image-add (late-loaded/renamed detectors).
- **Backend guard:** a fishhook-only `subMain` silently disables every ObjC `%hook` group.
  ObjC groups must always route through a method-capable substitutor; fishhook selection
  may only affect C groups.
- **EnvVars lifecycle:** NSProcessInfo hooks must install before app code runs and before
  the cached `environment` is read; currently the cached snapshot leaks because the getter
  hook is commented out.

### C0-5. Static ruleset coverage (`JailbreakMisc.plist` + generated rules)

Stop relying on generated dpkg rules for Shadow's own artifacts: add static entries for
`/Library/Shadow`, `/Library/ShadowSettings.bundle`, `/usr/lib/libShadow*`, `/usr/lib/libSandy.dylib`,
`/jb`, Cydia/Sileo/Zebra/Dopamine app paths, `shdw`/`dyldprobe` paths. Expose one atomic
ruleset-generation counter so libc directory/path caches invalidate immediately on reload.

---

## Phase 1 — P0: crashes, ABI violations, active leaks

Ordered globally; items within a wave are independent once C0 lands.

### Wave 1a — Dead/wrong hooks (cheap, high value)

| Fix | Where | Kills |
|---|---|---|
| `+[NSThread callStackReturnAddresses]` / `+[NSThread callStackSymbols]` (class methods, filter by address) | NSThread.x:5-30 | stack enumeration of Shadow frames |
| `-isMacCatalystApp` (correct selector) | NSProcessInfo.x:43 | dead FakeMac selector |
| Activate `-environment` (filter cached dict, not unsetenv) + add `-arguments` | NSProcessInfo.x:3-39,63-65 | cached env/argv detection |
| Remove NSURLRequest constructor hooks (nothing leaks at construction; enforce at consumers) | NSURL.x:151-185 | nil/nonnull traps |
| Remove `NXMapGet`/`NXHashGet` (dead: internal callers exempt; wrong choke point) | objc.x:71-97 | dead class-hiding path |
| Remove blanket `fn_enosys` → typed wrappers; `posix_spawn*` return error directly, never `-1/errno` | sandbox.x:156-188 | spawn contract violation, ENOSYS fingerprint |
| Delete `NSFileAppendOnly=YES` spoofs (attributes + filesystem attributes) | NSFileManager.x:319-330,344-355,407-418 | Shadow fingerprint + corrupted app queries |
| Activate `DCDevice isSupported`/`DCAppAttestService isSupported` under the toggle (opt-in: attestation fails closed) | DeviceCheck.x:3-9 | "unsupported" fallback bypass |

### Wave 1b — ABI/crash fixes

| Fix | Where |
|---|---|
| `statvfs/fstatvfs`: never touch NULL buf, only `ST_RDONLY` in `f_flag`, preserve original failure | libc.x:250-330 |
| `lstat`: init struct, `S_ISLNK`, no uninitialized copy on failure | libc.x:349-373 |
| `open/openat`: read mode only when flags require, promoted `mode_t`, match `.jbroot` as exact component | libc.x:905-977 |
| `__opendir2`: correct `(const char *, int flags)` prototype | libc.x:979-986 |
| `sandbox_check`: decode arity by `sandbox_filter_type`, deny file-read/write + jailbreak mach-lookup for app probes | sandbox.x:92-119 |
| `fcntl`: switch on command arity/type, `F_CHECK_LV` only on success + valid LV struct | sandbox.x:121-154 |
| `syscall`: arm64/arm64e register-preserving trampoline; never read absent args | syscall.x:5-57 |
| `method_getImplementation`/`class_getMethodImplementation`: NULL for protected Method/class/IMP; remove header-cast-to-IMP | objc.x:99-125 |
| `fileExistsAtPath:isDirectory:`: set `*isDirectory=NO`; preflight all existence/readability before `%orig` | NSFileManager.x:76-143 |

### Wave 1c — Active leaks

| Fix | Where | Kills |
|---|---|---|
| Atomic filtered dyld snapshot (lock-free read); remove `/System` blanket admission | dyld.x:6-38,76-114,302-380 | index/name/header incoherence leaks |
| `dladdr`: zero `Dl_info`, return 0 for restricted; delete RTLD_NEXT loop; NULL for `dyld_image_path_containing_address`; hook the exported alias | dyld.x:116-184,412-439 | infinite loop, dli_* leaks, contradictory attribution |
| `objc_copyImageNames`: build filtered malloc'd NULL-terminated array, handle `outCount==NULL`; `class_getImageName` → NULL; `objc_copyClassNamesForImage` → zero count | objc.x:17-58 | full image list leak |
| Class lookup/enumeration: `objc_getClass/LookUpClass/MetaClass`, `objc_getClassList`, `objc_copyClassList`, `objc_enumerateClasses` | objc.x (new) | Shadow/HookKit class discovery |
| `dlsym` symbol policy table: return replacement pointers for hooked APIs, NULL for protected; thread-local `dlerror`; correct `RTLD_NEXT` caller capture | dyld.x:9,382-410 | fishhook bypass, dlerror cross-thread state |
| `task_info`/`_dyld_get_all_image_infos`: never deref remote task address; filtered mirror for untrusted | dyld.x:282-300,590-598 | remote-address crash, real-array traversal |
| `readlink/readlinkat/realpath`: classify returned target; zero buffers on fake failure; free NULL-allocated results | libc.x:18-66,639-649 | symlink target disclosure |
| `symlink` (and `createSymbolicLinkAtPath/URL`): validate destination + relative resolution | libc.x:663-670, NSFileManager.x:569-590 | app-home alias creation |
| Enumerator ownership: persistent app-ownership context; fast-enumeration filter via `countByEnumeratingWithState:objects:count:`; wrap errorHandler; `fileAttributes`/`directoryAttributes` | NSFileManager.x:3-73,154-266 | for-in bypass, non-nil restricted enumerators, metadata leaks |
| Normalize directory bases to absolute cwd-joined once | NSFileManager.x:178-266,423-440 | relative-parent filtering bug |
| Mount sanitizer (C0-3) applied | libc.x:119-179,181-248 | mount-table enumeration |
| `csops`: sanitize status word at `useraddr` after success, clear debug/platform flags only, never execute-then-fail MARKKILL | syscall.x:59-87 | platform/debug inspection, CDHASH leak |
| `vm_region*`: skip restricted intervals, return next unrestricted mapping; never contradict protection/max_protection | mem.x:3-35 | executable-map enumeration, blanket-NX fingerprint |
| `NSURLSession` blocked-task helper (C0-3) | NSURL.x:99-148 | hangs, nonnull traps |
| Hidden-app predicate (C0-3) applied to all workspace results + scheme/open queries | LSApplicationWorkspace.x:11-162 | jailbreak app proxies |
| `NSString completePath...`: filter results after `%orig`, recompute safe completion | NSString.x:103-123 | partial-prefix probes |
| `+bundleForClass:` → main bundle for restricted classes (nonnull contract) | NSBundle.x:45-50 | nonnull crash |
| NSURL `URLByResolvingSymlinksInPath`/`fileReferenceURL`: post-filter result | NSURL.x:53-58,69-75 | alias resolution leaks |
| `getppid`: 1 only to app/detector callers; store original pointer | libc.x:892-894 | parent-debugger test (keep), cross-tweak regression (fix) |

---

## Phase 2 — P1: wrong semantics, incomplete object coverage

- **Error semantics everywhere:** all synthetic errors through the C0-3 factory (file layer
  P1-1, arrays/dicts/data write errors, NSURL promised values). Clear out-params on failure.
- **Async contracts:** never invoke blocked-path completions synchronously (NSFileManager
  `getFileProviderServices...`, NSFileVersion `getNonlocalVersions...`, NSString HTML
  loaders); dispatch sanitized completion asynchronously. NSURLSession via blocked-task helper.
- **NSFileVersion objects:** hook `-URL` and `-removeAndReturnError:`; filter version arrays;
  check receiver URL in `replaceItemAtURL:`; set `outError` on denial in
  `removeOtherVersionsOfItemAtURL:`.
- **NSFileWrapper containment:** associate source URL; filter `fileWrappers`,
  `regularFileContents`, `symbolicLinkDestinationURL`, `serializedRepresentation`;
  check `originalContentsURL` + tree in `writeToURL:`; `matchesContentsOfURL:` → NO on restricted.
- **NSFileHandle fd surfaces:** `initWithFileDescriptor:...`, `fileDescriptor`, read/write
  methods — resolve fd via `F_GETPATH`, deny restricted, pass pipes/sockets.
- **NSURL resource APIs:** `getResourceValue:forKey:error:`, `resourceValuesForKeys:error:`,
  cache-mutation APIs, bookmark resolution (post-filter target, stale/output clearing).
- **NSBundle metadata:** `infoDictionary`, `bundlePath/URL`, `executablePath/URL`,
  `resourcePath`, auxiliary executables, `isLoaded`/`load`/`preflight`/`unload`.
- **UIApplication:** `openURL:` variants → NO/async completion, no LaunchServices contact.
- **UIImage:** `imageNamed:` variants → nil for restricted bundles/exact protected basenames.
- **sysctl:** validate MIB, handle `KERN_PROC_ALL` (3-element), filter kinfo_proc entries,
  size-only + short-buffer semantics; clear `P_TRACED` only on valid success.
- **sigaction/signal aliases:** sanitize `oact` only after success; consistent default
  disposition; hook `signal`/`bsd_signal`/`__sigaction`.
- **Mach/sandbox ports:** `task_for_pid`/`host_get_special_port`/`task_get_special_port` —
  call original, hide only unexpected elevated success, deallocate rights, preserve
  `TASK_BOOTSTRAP_PORT`; share one exact service matcher (drop `com.ex`) across bootstrap
  hooks + sandbox.
- **readdir cache:** never cache `F_GETPATH` failure as allowed; fail closed on unresolved
  valid dir vnodes; refresh on ruleset generation; clear on `closedir`. Hook public
  `opendir`/`fdopendir`/`scandir(_b)`.
- **getenv:** implement actual filtering (DYLD_*, safe-mode, JAILBREAKD_*, PATH sanitize,
  thread-local storage); activate the group.
- **exec family:** typed wrappers parsing `execl*` varargs, `ENOENT` for hidden, stock-like
  `EPERM` for app-origin fork/vfork, external callers pass.
- **`imp_getBlock`:** inspect block ABI `invoke` pointer, not trampoline image.
- **`getmntinfo_r_np`, `sysctlbyname`, `__sysctlbyname`, `csops_audittoken`:** same policies
  as public symbols.
- **Direct proxy/query surfaces:** `LSApplicationProxy`/`LSBundleProxy` lookups,
  `enumerateBundlesOfType:block:`, document/user-activity queries.
- **NSFileManager:** `setAttributes:ofItemAtPath:error:`, `URLForDirectory:...`,
  `URLsForDirectory:inDomains:`, `containerURLForSecurityApplicationGroupIdentifier:`,
  `mountedVolumeURLsIncludingResourceValuesForKeys:options:`.
- **Runtime-existence guards** for unavailable selectors (NSFileVersion iOS-absent APIs,
  deprecated NSFileManager selectors) — kills method-inventory fingerprinting.
- **DeviceCheck ABI:** encoding-aware hooks for `UBReportMetadataDevice.is_rooted` and
  `EnrollParameters.jailbroken`; skip unknown encodings.

---

## Phase 3 — P2: completeness, sibling symbols, SDK churn

- **dyld:** durable `dyld_all_image_infos` post-publication mirror (rebuild on every add;
  inline-hook notifier; owned UUID storage; grow-on-demand buffers); `_dyld_register_for_image_loads`
  /bulk/`_dyld_objc_notify_register`/`objc_addLoadImageFunc` via authenticated tail-branch thunks
  (never invoke callbacks from Shadow); `_dyld_process_info_*`/snapshot APIs; address-attribution
  siblings (`_dyld_images_for_addresses`, slide, uuid, installname, unwind); `dlclose` mirror
  trigger; `NSAddImage`/`NSLookupSymbolInImage`/`NSVersionOfRunTimeLibrary`; `dlopen` tokenized/
  rpath resolution with explicit caller; CFBundle* symbol lookup wrappers.
- **objc:** `objc_setHook_getImageName/getClass` chaining (filtered proxy as `outOldValue`);
  `class_copyMethodList`, `class_getInstanceMethod`/`class_getClassMethod`,
  `_method_getImplementationAndName`, `class_getMethodImplementation_stret`, `objc_copyClassesForImage`.
- **C layer:** raw `SYS_openat`/`SYS_fstatat`/`SYS_csops`/`SYS_sysctl` dispatcher cases;
  `__syscall`; protected-open/authenticated variants; `stat64` family; remaining `*at`;
  `getattrlistat`/`fgetattrlist`/`getattrlistbulk`; `proc_listpids`/`proc_pidpath`/`proc_pidinfo`;
  `system`/`popen`/`wordexp`; `mach_vm_region_info*`; bootstrap `*2/3/per_user`;
  `pid_for_task`/`mach_port_names`/exception ports; `_NSGetEnviron`; `sandbox_check_by_audit_token`;
  jailbreak-specific ioctl only on resolved vnode/dev fds.
- **Foundation/UI:** NSString write APIs; WebKit request/string HTML loaders; immutable
  `-[NSArray initWithContentsOfURL:]`, `NSMutableCharacterSet`; LaunchServices/MobileInstallation
  payload content filtering (restricted app IDs inside allowed files); late-loaded detector-class
  hook retry via image-add callback.
- **Residual (document, do not fix):** direct inline `svc` bypasses all userspace symbol hooks.

---

## Consolidation & de-hooking (over-hooking audit)

**Remove** (dead, wrong, or fingerprinting — no fix justifies keeping them):
- `NSFileAppendOnly` attribute spoofs (3 sites)
- Blanket `ENOSYS` `fn_enosys` exec/fork hooks (replaced by typed wrappers)
- `vm_region` blanket-XO clearing (replaced by restricted-interval skipping)
- NSURLRequest constructor hooks (4)
- `NXMapGet`/`NXHashGet`
- Commented-out/inactive: `getenv` group install (reactivate or delete), DCDevice `isSupported`
  (reactivate under toggle), NSProcessInfo environment (reactivate)
- `macCatalystApp` wrong-selector hook (rename, keep behind FakeMac)

**Consolidate to one shared helper** (kills duplicated logic + future drift):
- Mount sanitizer → 6 statfs-family hooks
- Error factory → every Foundation file hook
- dirfd resolver → all `*at` hooks
- Hidden-app predicate → all LSApplicationWorkspace + openURL
- Blocked-task helper → all NSURLSession overloads
- Scheme/bundle-ID lists → Core/Backend, one place
- Enumerator ownership + filter → both enumerator creation methods + fast enumeration
- DeviceCheck third-party classes → plist-driven list with one install loop (~30 hand-written
  `%hook` blocks today; exact selector list stays data)

**Keep (earned their place):** direct path-based Foundation wrappers, stat/access/open denials,
ptrace PT_DENY_ATTACH, bootstrap lookup denials, dyld snapshot facade, symlink-target checks.

---

## Verification

- **Build:** `make` (theos) after each wave; no new warnings; arm64/arm64e slices.
- **On-device adversarial matrix** (rootless + rootful):
  - Paths: literal, symlink alias (app-home `.jbroot`), file-reference URL, relative, `..`
    traversal, case variants, nonexistent-then-created write probes, `/jb` variants.
  - Enumeration: direct `nextObject`, `for…in`, subpaths, attributes of entries, errorHandlers.
  - Images: `_dyld_image_count/name/header/slide` coherence, `all_image_infos` after load/unload,
    `dlsym` of hooked symbols, `RTLD_NEXT`, `dladdr` on Shadow frames, `objc_copyImageNames`,
    class list/copy/enumerate, method lists on tweak classes.
  - C: statfs family vs real mounts, getmntinfo/getfsstat counts, `csops` status word,
    `syscall(SYS_ptrace)` raw, spawn of `/bin/sh`, sandbox file-read probe, bootstrap lookup,
    `vm_region` consistency vs known app code, fd 0–2 reuse.
  - Foundation/UI: NSProcessInfo env/args, NSThread stack APIs, canOpenURL case variants,
    LSApplicationWorkspace all variants, NSURLSession blocked-task completion, NSBundle metadata.
  - Fingerprint checks: error domains/userInfo, ENOSYS-vs-stock failures, flag contradictions.
- **Regression:** benign-app smoke suite (files in sandbox, HTTP requests, bundle resources,
  app-group containers) must pass unchanged through all waves.
- **Final gate:** a real detector suite (IOSSecuritySuite/freeRASP + hand-written probes
  covering the matrix) on device; no positive results, no crashes, no hangs.

## Top risks

1. dyld mirror internals (private ABI, dyld4 ordering, arm64e) — device-test early, prototype first.
2. syscall trampoline assembly (PAC, stack alignment) — isolate behind build flag until proven.
3. posix_spawn/fork semantics — entitled apps legitimately spawn; caller-gate carefully.
4. sandbox variadic arity matrix varies by OS — fail to original on unknown commands.
5. Caller-ownership inversion — highest-value Core change, highest regression risk; TLS bypass
   for Shadow internals must be airtight or Shadow deadlocks itself out of its own reads.

---

## Execution status (2026-08-07)

All Phase 0 (shared foundations) and Phase 1 (P0) items implemented and merged, 50 commits
(`v5: plan-wave-*`) on top of 95bdeb8. Full aggregate `make` passes: exit 0, 0 errors
(34 warnings = pre-existing arm64e-ABI toolchain noise, present in untouched files too).
armv7/armv7s compile clean; legacy-flavor link verification requires the legacy dep staging.

### Landed

- **Phase 0**: operation-aware read/write intent (kShadowRestrictionOperation, write probes
  skip existence gates); caller-truth inversion (isCallerExternal = truth only for
  Shadow-owned images / SHADOW_INTERNAL_SCOPE; own-ranges collector repointed to
  Shadow-owned artifacts); error factory (NSCocoaErrorDomain + path/URL userInfo);
  scheme case-insensitivity (Backend + Ruleset); bundle-ID predicate (+ ruleset
  BlacklistBundleIDs); isProtectedImagePath exact-name predicate; detector escalation
  force-installs objc/tweakclasses groups, detector-name list extended, envvar group +
  NSProcessInfo env/args activated at ctor; safe-group defaults flipped
  (ObjCRuntime/TweakClasses/SymLookup/LowLevelC/HideApps); atomic ruleset-generation getter
  + generation-tagged decision cache; static ruleset entries for Shadow's own artifacts.
- **File layer**: NSFileAppendOnly spoofs deleted; preflight-before-%orig on existence/
  readability/contents (+ *isDirectory cleared); enumerator fast-enumeration filtering,
  unconditional, restricted-root reject, errorHandler wrap; symlink both-sides validation;
  NSURL result post-filtering + resource values + bookmark resolution; NSURLSession
  blocked-task helper (real cancelled task, one async error); NSURLRequest constructors
  removed; NSFileVersion object protection + async completions; setAttributes/
  URLForDirectory/mountedVolumeURLs/containerURL; full error-factory + write-intent sweep.
- **C layer**: shared dirfd resolver (+ linkat/symlinkat/renameat/mkdirat/utimensat/
  fchmodat), shared mount sanitizer (remove+compact, no synthetic MNT_SNAPSHOT) +
  getmntinfo_r_np; exact .jbroot component; readlinkat/realpath target handling; readdir
  fail-closed; getenv filtering; sysctl KERN_PROC semantics; caller-gated getppid;
  stat64/protected-open variants; csops clear-only + MARKKILL pre-reject; vm_region
  interval-skipping; hide-only-elevated Mach ports + shared bootstrap matcher;
  sandbox_check file-op denials; typed exec wrappers (no ENOSYS); signal aliases;
  raw SYS_openat/fstatat/csops/sysctl dispatcher + __syscall; sysctlbyname, csops_audittoken,
  _NSGetEnviron, system/popen, bootstrap 2/3/per_user, sandbox_check_by_audit_token.
- **dyld/objc**: own-ranges repoint; NXMapGet/HashGet removed; method-getter IMPs → NULL;
  objc_copyImageNames fully filtered; class lookup/enumeration hooked; dlsym policy table +
  thread-local dlerror + RTLD_NEXT caller capture; dladdr zeroed; /System admission removed;
  all_image_infos patch unpref-gated; imp_getBlock block-invoke inspection; CFBundle*
  wrappers; objc_setHook chained proxies; method-metadata hooks; dlopen tokenized resolution.
- **Foundation/UI**: NSThread class-method hooks + symbol filtering; isMacCatalystApp +
  environment + arguments; LSApplicationWorkspace bundle-ID predicate; NSAttributedString
  async failure; DeviceCheck isSupported + encoding-aware ABI hooks; UIApplication openURL
  variants; UIImage imageNamed variants; NSBundle metadata/load-state; NSString
  completePath post-filter + write APIs + WebKit loaders; collection error normalization +
  missing variants.

### Deferred (TODO comments in code; device-test territory)

- dyld callback tail-branch thunks, _dyld_objc_notify_register/objc_addLoadImageFunc,
  _dyld_process_info_*/snapshot APIs, NSAddImage family, mirror grow-on-demand,
  notifier-inline rebuild (dyld.x)
- Recursive copy/move/remove/trash descendant preflight (needs unhooked subtree walk)
- NSFileWrapper full containment (fileWrappers/regularFileContents/serializedRepresentation)
- NSFileHandle fd-based surfaces
- LaunchServices/MobileInstallation payload content filtering
- Late-loaded detector-class hook retry (dylib.x watcher wiring)
- DCDevice/AppAttest async generation APIs (cannot forge server-verifiable artifacts)
- wordexp / pid_for_task / mach_port_names / task_get_exception_ports upgrade paths (conservative pass-throughs)

### Remaining verification

- On-device adversarial matrix (rootless + rootful) from the Verification section —
  requires the dyldprobe tool + detector suite on hardware
- Legacy armv7 packaging pass (build.sh pass 3) with legacy dep staging
