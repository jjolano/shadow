# SDK compatibility research

## Scope and confidence

Compared the installed `iPhoneOS15.6`, `16.5`, `17.5`, `18.6`, and `26.5`
SDKs. Header availability is the public compile-time contract; a `.tbd` entry
only proves that a symbol was present in that SDK's linker stub. It does **not**
provide a supported ABI or prove availability on every device build. Treat every
private-symbol row below as a `dlsym` + device-probe candidate, never as an
automatic hook.

## Already compatible or runtime-gated

| Surface | Header evidence | Existing Shadow comparison | Result |
| --- | --- | --- | --- |
| DeviceCheck / App Attest | `System/Library/Frameworks/DeviceCheck.framework/Headers/DCAppAttestService.h` and `DCDevice.h` have the same public selectors in all five SDKs: `sharedService`, `supported`, `generateKey…`, `attestKey…`, `generateAssertion…`; `currentDevice`, `supported`, `generateToken…`. | No post-iOS-15 public selector requires a new compatibility hook. App Attest artifacts are designed for server validation, so fabricating them is not a client-side compatibility solution. | Stable. Keep this as a server-policy boundary, not an SDK gap. |
| Public Objective-C class enumeration | `iPhoneOS16.5.sdk/usr/include/objc/runtime.h` declares `objc_enumerateClasses` with iOS 16 availability; it is absent from the 15.6 header. | `ShadowCore.dylib/hooks/Runtime/objc_hidetweakclasses.x` resolves it with `dlsym` and filters it only when present. | Already runtime-gated. Test it on 16+ devices, including the iOS 15 floor where the symbol is absent. |
| Public dyld image state | `mach-o/dyld.h` retains the public image-list APIs across the set. `mach-o/dyld_images.h` adds `dyld_image_dyld_moved` and a 16-byte alignment annotation for `dyld_all_image_infos` after 15.6; `mach/task_info.h` keeps `TASK_DYLD_INFO` layout stable. | `ShadowCore.dylib/hooks/Runtime/dyld.x` uses `sizeof(struct dyld_all_image_infos)` and an all-image-info size check rather than a hard-coded structure size. | No new public dyld hook indicated; retain a device canary for its mirrored task-info reply. |
| Newer mount information | `getmntinfo_r_np` is an iOS 16-era export. | `ShadowCore.dylib/hooks/FileHiding/libc.x` installs it through `dlsym` as optional. | Already runtime-gated. |

Apple's public [DeviceCheck overview](https://developer.apple.com/documentation/DeviceCheck),
[DCAppAttestService reference](https://developer.apple.com/documentation/devicecheck/dcappattestservice),
and [server-validation guidance](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
support the App Attest boundary above.

## Detector-facing audit candidates

`Reusable policy` means the existing policy primitive has the right input
shape. It does not mean the new API can safely be hooked without the stated
device test.

| Priority | Surface and exact local evidence | Existing coverage | Reusable policy / safe next step |
| --- | --- | --- | --- |
| P0 | `freadlink(int, char *, size_t)` is publicly declared iOS 16 in `iPhoneOS16.5.sdk/usr/include/sys/unistd.h:191`. The `SYS_freadlink` number and `_freadlink` stub export already occur in the 15.6 SDK (`usr/include/sys/syscall.h:591`, `usr/lib/libSystem.B.tbd:2442`). | `libc.x` hooks `readlink` and `readlinkat`, but has no `freadlink`; `RawSyscalls.def` has no `SYS_freadlink`. | Reuse `shdw_fd_path_restricted` for an external caller's descriptor. Probe first for the required descriptor mode, stock errno, and how to safely apply the existing symlink-target policy: public-header availability alone would incorrectly exclude the iOS 15 floor. |
| P0 | `mkfifoat(int, const char *, mode_t)` and `mknodat(int, const char *, mode_t, dev_t)` are iOS 16 public APIs in `iPhoneOS16.5.sdk/usr/include/sys/stat.h:394-395`; their syscall numbers are 553/554 in the later SDK headers. | `libc.x` now applies `shdw_at_path_denied(dirfd, path)` to both, and `RawSyscalls.def` covers the corresponding raw paths. | Runtime-gated on iOS 15 through `dlsym`; device-test the denial errno and direct-`syscall`/SVC route. These are plausible write-privilege probes under hidden/rootless paths. |
| P0 | `F_GETPATH_NOFIRMLINK` is `102` and returns a descriptor's full path without firmlinks. It is already present in **15.6** at `usr/include/sys/fcntl.h:307` (and remains through 26.5), so it is not a post-15 SDK delta. | `sandbox.x` filters both `F_GETPATH` spellings for external callers after a successful path-returning call; `PathPolicy` itself bypasses that branch. | Device-test `F_GETPATH` and `F_GETPATH_NOFIRMLINK` together for buffer/errno behavior. This is an iOS 15 rootless-floor audit item. |
| P1 | `fdscandir`, `fdscandir_b`, `scandirat`, and `scandirat_b` first appear in `iPhoneOS26.5.sdk/usr/include/dirent.h:179-201`, each available iOS 26.4. | Shadow filters `readdir`, `readdir_r`, and raw `getdirentries64`, but has no scanner wrapper. | `fdscandir` can reuse the fd predicate and `scandirat` the dirfd predicate, but neither predicate filters a returned entry array. Device-probe whether the implementation traverses the already hooked `readdir`; if not, use a runtime-gated wrapper that filters its copied result. |
| P1 | `_getenv_copy_np` is observed only in the 26.5 local linker metadata: `iPhoneOS26.5.sdk/usr/lib/libSystem.B.tbd:1126` (also `usr/lib/system/libsystem_c.tbd`). It has no supplied public declaration. | `libc_envvar.x` hooks `getenv`; `syscall.x` provides a filtered `_NSGetEnviron` snapshot. Neither references this symbol. | No safe ABI assumption. First dlsym it on a device and establish its signature, allocation/ownership, and whether it exposes values hidden by `getenv`; only then consider a hook. |

### Raw-call implication

`ShadowCore.dylib/hooks/FileHiding/RawSyscalls.def` is the authoritative raw
syscall registry. It covers `SYS_readlink`, `SYS_openat`,
`SYS_getdirentries64`, `SYS_mkfifoat`, and `SYS_mknodat`; `SYS_freadlink`
remains deliberately probe-gated. A libc-only fix for it would not cover a
detector that calls `syscall(2)` or a direct SVC path.

## Private-runtime watchlist (probe, do not blind-hook)

| Candidate family | First local linker-stub evidence | Why it merits a probe |
| --- | --- | --- |
| ObjC class enumeration SPI | `iPhoneOS16.5.sdk/usr/lib/libobjc.A.tbd` contains `__objc_beginClassEnumeration`, `__objc_endClassEnumeration`, `__objc_enumerateNextClass`, and `__objc_getRealizedClassList_trylock`. | A detector could enumerate classes outside public `objc_enumerateClasses`. No public prototypes or Shadow references were found. Mach-O spelling does not establish the `dlsym` spelling or ABI. |
| ObjC image/hook SPI | `iPhoneOS17.5.sdk/usr/lib/libobjc.A.tbd` contains `_objc_addLoadImageFunc2`; 26.5 contains `__objc_setHook_methodSetImplementation`. | These may provide an image-load or method-mutation observation route distinct from Shadow's public hooks. Determine signatures and use before any interception. |
| dyld process SPI | `iPhoneOS16.5.sdk/usr/lib/libSystem.B.tbd` lists `_dyld_process_has_objc_patches`, `_dyld_process_register_for_image_notifications`, `_dyld_process_snapshot_for_each_image`, and `_dyld_image_get_file_path`. | The names suggest parallel patch/image observations, but they have no public headers here. Audit presence and behavior on device only. |

## Low-priority process/debug canaries

`TASK_SECURITY_CONFIG_INFO` first appears in the supplied 18.6
`usr/include/mach/task_info.h`; `TASK_IPC_SPACE_POLICY_INFO` first appears in
26.5. Both expose opaque configuration fields, not a demonstrated jailbreak or
injection signal. Keep them as regression-test canaries rather than spoofing
targets unless a detector actually uses them.

## Recommended compatibility test matrix

1. On the iOS 15 rootless floor, probe `dlsym("freadlink")`, `F_GETPATH`, and
   `F_GETPATH_NOFIRMLINK`; record return value, errno, and any visible path.
2. On iOS 16+, test public `freadlink`, `mkfifoat`, and `mknodat` through both
   libc and raw-syscall paths against a hidden/rootless path.
3. On iOS 26.4+, test every scanner variant on a directory containing hidden
   entries, and check whether the existing `readdir` hook was traversed.
4. Keep the private symbols in a non-blocking `dlsym` inventory. Add a hook
   only after a real device establishes ABI and detector relevance.

## Historical app target: Unveil

The likely missing test app is [Unveil](https://unveilapp.com/), a $4.99 iOS
system/security analysis app made by Unveil Security LLC. Its official page
describes sandbox-local software-modification/security checks plus CPU,
memory, OS, disk, filesystem, and network inspection; its changelog contains
only `v1.0.0 - Initial Release`. The unc0ver site promoted it as built by its
lead developer and credits pwn20wnd and the unc0ver team. The surviving
open-source [Reveil](https://github.com/Lessica/Reveil) project identifies
itself as a replication and says Unveil received no updates after its initial
release.

This is a useful black-box detector target, not a detector SDK: no public
source for the original implementation or reliable bundle ID was found. The
original App Store listing is reportedly no longer available; use the
official site for provenance and Reveil only as an inspectable approximation,
not as proof of Unveil's exact checks.
