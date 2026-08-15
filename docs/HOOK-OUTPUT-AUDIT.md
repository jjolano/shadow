# Hook Output-Correctness Audit

> Historical audit snapshot from 2026-08-08. Paths reflect the source layout
> at that date; current release verification lives in
> [`STEALTH-HARDENING-PLAN.md`](STEALTH-HARDENING-PLAN.md).

Adversarial audit of the tweak's hooks from a **detector's** lens: every output our
hooks produce that is *wrong, self-inconsistent, or impossible on stock iOS* is a
fingerprint a jailbreak detector can cross-check. Fixes applied; residuals documented.

Build verified: `make` is green (legacy/arm/arm64/arm64e debs; `ShadowCore.dylib`
compiles with all fixes on both arm64 and arm64e).

---

## Method

Read all 24 hook files end-to-end plus the classification/error-factory code in
`Shadow.framework/Core.m` / `Core+Utilities.m`. Correctness dimensions checked per
hook:

1. errno discipline (success never clobbers; failure sets what stock would).
2. Return/out-param contracts (`isDirectory:`, `NSError**`, nonnull getters,
   positive-errno for `posix_spawn`, etc.).
3. **Cross-API coherence** — the detector's #1 weapon: the same logical datum
   reported identically across sibling APIs.
4. In-band fingerprints (values stock never produces).
5. Truth-scope correctness (`isCallerExternal` / `SHADOW_INTERNAL_SCOPE`).
6. ABI/type correctness (varargs, struct returns, NULL-buf edge cases).

Severity: **FIX** (provably wrong, exploitable) / **SUSPECT** (needs device check) /
OK (verified coherent).

---

## Findings & fixes

### Fixed (all compile-verified)

| # | Where | Finding | Fix |
|---|-------|---------|-----|
| 1 | `mem.x` vm_region family (4 loops) | Skip loop re-calls original with `*address` unchanged → XNU returns the region *containing* `*address` (start, not advanced) → **infinite spin** on first restricted region (full-map scans hang the thread; 100% CPU). | `*address += *size` before re-call. |
| 2 | `NSString.x` `stringByResolvingSymlinksInPath`/`stringByStandardizingPath` | Returned `self` (unresolved `..`-laden input) when result restricted — a `..`-containing output is stock-impossible and contradicts `realpath` (ENOENT/EACCES) and `NSURL` (nil). | Resolution: return `[self stringByStandardizingPath]`. Standardization: pure pass-through (lexical, leaks nothing). |
| 11 | `NSURL.x` `URLByResolvingSymlinksInPath`/`URLByStandardizingPath` | nil for restricted — stock never nils these on a valid URL. | Same as #2: receiver-standardized / pass-through. |
| 3 | `syscall.x` `_NSGetEnviron` | Filtered only 4 vars; `getenv` filters all `DYLD_*`/`JAILBREAKD_*`+PATH → contradiction. | Full getenv-policy filter + PATH component strip into thread-local snapshot. |
| 4 | libc.x+syscall.x sysctl `KERN_PROCARGS2` / per-pid queries | `[NSProcessInfo arguments]` filtered but kernel argv raw; per-pid `KERN_PROC_PID`/`PROCARGS2` of JB daemons unfiltered. | New `shdw_procargs2_filter` (libc.x, shared via hooks.h) rebuilds the payload in place to match the filtered argv/env views; restricted other-pids answer ENOENT. |
| 5 | `dyld.x` mirror `imageFileModDate` | Hardcoded 0 — raw readers cross-check `stat()` → mismatch. | Fill real `st_mtimespec.tv_sec`. |
| 6 | `dyld.x` dlsym denial `dlerror` | Message "library not found" (dlopen's); stock dlsym says "symbol not found: <name>". | `shdw_dyld_set_error("symbol not found: %s")`. |
| 7 | `iokit.x` | `kIOReturnNotFound` (stock = success + empty iterator); `IOServiceOpen` NotFound on an existing service. | Empty-iterator helper; `kIOReturnUnsupported`. |
| 8 | `NSArray`/`NSDictionary`/`NSData` write methods | Write paths classified with **read** intent → exact-file-rule targets (`/usr/lib/*.dylib`) writable via `writeToFile:` while `createFileAtPath:` denies. | Pass `kShadowRestrictionOpWrite`. |
| 9 | `NSThread.x` `callStackSymbols` | Restricted frames dropped without renumbering → non-contiguous index column (stock never produces). | Reindex surviving frames; keeps counts aligned with `callStackReturnAddresses`. |
| 10 | `NSProcessInfo.x` FakeMac | `isMacCatalystApp`/`isiOSAppOnMac` = YES to every caller — universal fingerprint (stock never YES) and breaks Mac-branching apps. | Group removed; installer is an inert no-op; `Hook_FakeMac` toggle inert. |
| 12 | `NSFileWrapper` `initSymbolicLinkWithDestinationURL:` | nil where stock never nil (no I/O at construction). | Hook removed. |
| 13 | `lstat`/`lstat64` NULL-buf | Restricted path answered ENOENT where stock says EFAULT. | NULL-buf replayed before classification. |
| 14 | `syscall.x` `replaced_syscall`/`__syscall` | `NSLog` per intercepted syscall (log noise + timing visibility). | Removed. |

### Residual (documented — accepted risk, not closed)

- **`extern char** environ` direct reads.** `getenv`/`_NSGetEnviron` now filter, but
  a detector that links the `environ` symbol (same address space) still sees
  `DYLD_INSERT_LIBRARIES=` etc. → the getenv-vs-environ *comparison* is the signal.
  Closing needs a libSystem `__environ` **data-symbol rebind** (risky: `setenv`/`putenv`
  rewrite/swap the real array; behavior is platform-dependent and not device-verified) —
  left as documented risk.
- **IOKit registry-plane enumeration.** `IORegistryEntryGetChildIterator` over
  `IOServicePlane` exposes any JB-named service class regardless of the
  `IOService(GetMatching)*`/`IOServiceOpen` fixes. Closing needs registry-iteration
  SPI hooks (hard). Left as documented risk.
- `NSFileVersion -URL` nil on a nonnull getter — reachable only from version objects
  obtained pre-hook; kept.

### Verified coherent (detector cross-checks that pass)

- Parent discipline: `getppid` = `sysctl` KERN_PROC_ALL/PID(self) = `sysctlbyname`
  kern.proc.* = `proc_pidinfo` pbi_ppid = 1; P_TRACED/P_SELECT cleared on both sysctl
  forms and raw dispatch.
- Mount family: `getfsstat`/`getmntinfo`/`getmntinfo_r_np`/`statfs`/`fstatfs`/
  `statvfs`/`fstatvfs` all filter the same records with count/bufsize semantics;
  `MNT_SNAPSHOT` never fabricated.
- Directory family: `readdir`/`readdir_r`/`getdirentries64`/`NSDirectoryEnumerator`
  (nextObject/allObjects/fast-enum) filter the same entries.
- Denial shapes: posix_spawn positive-errno, exec/access/stat/open ENOENT, bootstrap
  `BOOTSTRAP_UNKNOWN_SERVICE`, `sandbox_check` → 1 (never -1).
- dyld/objc: image-count/name/header/slide + dladdr/dlopen/dlsym +
  objc_copyImageNames/getClassList share one snapshot/predicate; blocked NSURLSession
  tasks complete exactly once, async, real NSURLErrorFileDoesNotExist; environment
  filtering matches across NSProcessInfo/getenv/PATH.

---

## Adversarial differential-test strategy

A detector fights these best with **differential + fuzz** checks, not by knowing what a
jailbreak "should" look like. Two modes:

1. **Fixed-pair differential** — the checks the fixes closed (assert each pair agrees):
   - Existence: `access(F_OK)` vs `stat` vs `lstat` vs `[NSFileManager fileExistsAtPath:]`
     vs `fopen` vs `realpath` vs `open` — all must report "not present" for a hidden path.
   - Resolution: `realpath` vs `stringByResolvingSymlinksInPath` vs
     `URLByResolvingSymlinksInPath` — no `..`/unresolved output, no nil on valid input.
   - argv: `[NSProcessInfo arguments]` vs `sysctl({KERN_PROCARGS2, self})` — equal.
   - env: `getenv("DYLD_*")` vs `*_NSGetEnviron()` vs `[NSProcessInfo environment]` —
     absent everywhere (**except** the raw `environ` symbol — residual, see above).
   - mod-date: `stat(imageFilePath)` vs `dyld_all_image_infos[].imageFileModDate`.
   - mounts: `statfs("/").f_flag` `MNT_RDONLY` vs `statvfs("/").f_flag` `ST_RDONLY`.
   - process list: `sysctl({KERN_PROC_ALL})` + `proc_listpids` + `ps`-equivalents all
     exclude jailbreak daemons; per-pid `KERN_PROC_PID`/`PROCARGS2` of a daemon → ENOENT.
   - error shape: a blocked file read's `NSError` carries `NSFilePathErrorKey`/
     `NSURLErrorKey` and `NSFileNoSuchFileError`.

2. **Differential fuzzing** — iterate inputs (path spellings, `..`, case, relative vs
   absolute, nonexistent targets, scheme case) asserting the SAME invariant across
   *every* reachable API. Per-pair fixes can't fully close this; it generates pairs the
   fixer didn't enumerate.

### Softer, universal

- **Timing**: even intercepted `stat`/`access`/`open` adds measurable latency (return-
  address classification + predicate + cache). Partly mitigated by the decision cache
  and fast C paths; not fully closable at hook level.
- **Exhaustive differential**: "call everything, flag any non-stock output".

**Recommended harness (device-run):** a probe launched *under Shadow* (hooks active
in-process) that runs the fixed-pair battery above over a set of representative hidden
artifacts, reports each check PASS/FAIL, and explicitly prints the two residual
surfaces' raw status (environ scan, IOKit registry service-name scan). This cannot run
in the Linux `tests/` harness (no HookKit); it is an on-device tool (mirror the
`tools/dyldprobe` layout if implemented).

### Harness coverage (implemented, Linux — runs + verifies here)

The engine half of the differential *can* run in the existing Linux harness (it drives
`-[Shadow isPathRestricted:options:]`, `isURLRestricted:options:` and the error
factory). Added `testDifferentialCoherence` to `tests/main.m`, which pins:

- **write-intent agreement (`#8`)**: an absent restricted exact-file target
  (`/usr/lib/libghost.dylib`) is read-allowed by the existence gate but denied by
  path-write and file-URL-write — the contract the NSArray/NSDict/NSData write-hook
  fix restored.
- **option-stack coherence**: a stable allowed-absolute-path verdict is invariant
  across `nil` / `@{}` / workingDir-only option stacks.
- **cross-entry-point differential (differential-fuzz)**: for a vector of restricted +
  allowed paths, `isPathRestricted:` == `isCPathRestricted:` == `isURLRestricted:` ==
  expected — any alias divergence is flagged.
- **error-factory shape (`#2`/`#11`)**: `fileNoSuchFileErrorForPath:`/`ForURL:` both
  yield `NSCocoaErrorDomain`/`NSFileNoSuchFileError` with `NSFilePathErrorKey` (and
  `NSURLErrorKey` for the URL variant) present.

Verification: `make test` in `tests/` (Docker GNUStep) — **117 passed / 0 failed**
(rootless), **145 passed / 0 failed** (rooted).

The **Darwin-surface half** (argv via `KERN_PROCARGS2`, `_NSGetEnviron`, dyld/objc
image list, mounts, `vm_region`, `callStackSymbols`, swizzling) still requires the
device-run probe — the Linux harness cannot load HookKit or these Darwin APIs.
