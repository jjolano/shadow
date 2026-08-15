# Stealth validation research

Research snapshot: 2026-08-13. This note distinguishes vendor-documented
behavior from observations that require a stock-device baseline.

## Supported environments are not primitive contracts

Current Dopamine `3.x` declares these rootless, semi-untethered ranges:

- arm64e: iOS 15.0–17.3.1;
- A12/A13: iOS 15.0–18.7.1 and 26.0–26.0.1;
- arm64: iOS 15.0–18.7.1.

That is a product compatibility declaration, not a promise that every release
exports the same kernel primitives
([Dopamine README](https://github.com/opa334/Dopamine/blob/3.x/README.md)).
In particular, Dopamine's current arm64 kernel-call implementation rejects
arm64e and disables itself on iOS 16 and later
([source](https://github.com/opa334/Dopamine/blob/3.x/BaseBin/libjailbreak/src/kcall_arm64.c#L109-L142)).
Kernel read/write availability therefore does not imply kernel-call or
persistent-hook availability.

palera1n targets checkm8 devices A8–A11 and T2. Its current manual describes
arm64, explicitly excluding arm64e, on iOS/iPadOS/tvOS 15–26 and bridgeOS
5–10, with rootless and rootful iOS modes
([manual](https://github.com/palera1n/palera1n/blob/main/docs/palera1n.1)).
The same manual's device section still contains an older 15.0–18.0 statement,
so Shadow must test the exact OS build instead of treating the broad upper
bound as verified compatibility. palera1n accepts a custom preboot PongoOS/KPF
module, but that requires a new jailbreak boot and is not a stable runtime
hook API
([manual](https://github.com/palera1n/palera1n/blob/main/docs/palera1n.1),
[PongoOS](https://github.com/checkra1n/PongoOS#readme)).

For every device row, probe and record these capabilities independently:

| Capability | Required proof |
|---|---|
| Kernel read | known-safe read succeeds |
| Kernel write | reversible scratch or owned-field write/readback succeeds |
| Kernel call | provider explicitly exposes it and a benign call succeeds |
| Persistent VFS hook | jailbreak documents a supported installation and removal API |

Do not infer one row from the jailbreak name. `libkrw` explicitly permits
partial providers and `ENOTSUP`, and warns that invalid kernel addresses may
panic
([API](https://github.com/Siguza/libkrw/blob/master/include/libkrw.h)). Neither
Dopamine nor palera1n currently documents a supported persistent VFS/vnode
hook API. Per-process kernel hiding therefore remains a capability-gated
spike, not a release commitment.

## Documented stock behavior

### Pathname APIs

Apple documents `-1` plus `ENOENT` for `open` when the named file or a required
component is absent
([`open(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/open.2.html)).
`stat` and `lstat` also use `ENOENT` for missing names, while differing in
whether a final symlink itself or its target is inspected
([`stat(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html)).
These contracts do not justify converting every failure to `ENOENT`: fixtures
must preserve stock `EACCES`, `ELOOP`, `ENOTDIR`, malformed-input behavior,
and output-buffer mutation.

Directory filtering must preserve packed `dirent` traversal, directory
position, repeated-call behavior, and zero-byte EOF
([`getdirentries(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getdirentries.2.html)).

### dyld views and notifications

Apple documents that `_dyld_image_count()` iteration is not thread-safe.
Registering an add-image callback immediately invokes it once for every
existing image, then for newly added images; remove callbacks run for removed
images
([`dyld(3)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/dyld.3.html)).

The independent memory oracle must obtain `all_image_info_addr`, size, and
32/64-bit format using `task_info(..., TASK_DYLD_INFO, ...)`
([XNU header](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task_info.h#L1968-L1990)),
then read `dyld_all_image_infos`. Apple defines its snapshot array,
notification pointer, and change timestamp and says a null `infoArray` means
the array is being modified and should be retried
([dyld header](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_images.h#L689-L716),
[structure](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_images.h#L813-L918)).

`DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT == 8` limits the structure's Mach notify
ports; it is not a documented cap on public add/remove callbacks. Shadow must
not use it to discard public callback registrations.

### Process and connection lifecycle

An XPC request expecting a reply must receive a reply dictionary correlated
to the original request
([`xpc_dictionary_create_reply`](https://developer.apple.com/documentation/xpc/xpc_dictionary_create_reply(_:))).
`XPC_ERROR_CONNECTION_INTERRUPTED` means the remote service exited; the named
connection remains reusable, but the client must resynchronize state.
`XPC_ERROR_CONNECTION_INVALID` means the connection is unusable
([interrupted](https://developer.apple.com/documentation/xpc/xpc_error_connection_interrupted-swift.var),
[invalid](https://developer.apple.com/documentation/xpc/xpc_error_connection_invalid-swift.var)).

PID alone is not a durable lease identity. XNU process identity includes PID,
`p_uniqueid`, and pidversion, and its validation always checks `p_uniqueid`
([XNU source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c#L2913-L3075)).
Use authenticated XPC connection death as the primary lease lifetime signal;
only use a userland unique-ID query after capability/ABI probing on that OS.

## Empirical stock-device work still required

Public documentation does not fully specify the observations a detector can
compare. Capture matching stock and Shadow runs on every supported OS/device
class for:

1. Exact return value, `errno`, output-buffer changes, symlink behavior, and
   relative/`*at` resolution for `open`, `stat`, `lstat`, `access`, and raw
   syscalls.
2. `getdirentries64` record layout, offsets, EOF, small-buffer behavior, and
   interleaved enumeration; the public manual covers `getdirentries`, not the
   exact private `getdirentries64` ABI used by current iOS.
3. dyld callback ordering across multiple registrations, concurrent
   `dlopen`/`dlclose`, snapshot retry behavior, and agreement between public
   APIs and `TASK_DYLD_INFO` memory.
4. Lease cleanup and reacquisition after normal exit, force-quit, crash,
   suspend, jetsam, PID reuse, daemon death, SpringBoard death, and userspace
   reboot. UIKit scene transitions are not reliable process-death signals;
   scenes may disconnect independently to reclaim resources
   ([UIKit lifecycle](https://developer.apple.com/documentation/uikit/managing-your-app-s-life-cycle)).
5. Timing distributions, not single samples: cold/warm launch, first probe,
   callback registration, and hidden versus ordinary paths.

Release rule: a mechanism is supported only when its mechanism-specific
harness probe matches the stock oracle and its lifecycle cleanup test passes
on that exact jailbreak, OS build, and architecture.
