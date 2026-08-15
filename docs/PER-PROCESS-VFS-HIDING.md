# Per-process VFS hiding on iOS 15–16

## Decision

Do **not** extend `VISSHADOW`, patch a shared vnode-op table, or patch the
syscall table. None provides safe per-process visibility.

The smallest technically correct mechanism is a jailbreak-supplied kernel
patch at XNU's pathname-lookup authorization seam, keyed by a process-unique
lease and returning `ENOENT` for a fixed component allowlist. Complete
directory concealment additionally needs post-`VNOP_READDIR` filtering.
Shadow should treat this as a gated research backend, not a promised feature:
stock Dopamine exposes kernel read/write and limited kernel-call primitives,
but no supported persistent kernel-hook facility.

## What `VISSHADOW` proves—and cannot provide

XNU defines `VISSHADOW` as “vnode is a shadow file” inside the named-stream
configuration, and `vnode_isshadow()` merely tests that flag
([definition](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/sys/vnode_internal.h#L288-L299),
[test](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/kpi_vfs.c#L2077-L2091)).
Its intended consumers implement resource-fork/named-stream backing files; XNU
sets the bit while creating those streams
([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_xattr.c#L407-L423)).
However, generic pathname lookup rejects any resolved vnode carrying the bit
inside a `NAMEDSTREAMS` build; it does not additionally require
`VISNAMEDSTREAM`
([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_lookup.c#L872-L882)).

Therefore `v_flags` write/readback proves that `shadowd` changed the global
vnode state, but an A/B `open`/`stat` probe while the lease remains active is
still required to prove the device kernel enforces it. The same unconditional
bit test exists in the iOS 15-era XNU tag
([iOS 15 source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8020.101.4/bsd/vfs/vfs_lookup.c#L872-L882)).
Even when effective, the bit has no process context: every process sees the
same result, which makes it unsuitable for broad jailbreak-path concealment.

## Correct hook points

Every ordinary `namei` lookup carries a `vfs_context_t`; XNU obtains its
associated process with `vfs_context_proc(ctx)`
([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_lookup.c#L165-L175)).
Lookup invokes MACF both before filesystem work and for each component,
including cached-name paths
([namei preflight](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_lookup.c#L446-L464),
[component check](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_lookup.c#L616-L638),
[cache path](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_cache.c#L1652-L1668)).
`vfs_context_proc` resolves the context's thread to its BSD process and falls
back to `current_proc()`
([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/kpi_vfs.c#L1330-L1362)).

A minimal lookup policy would:

1. Check `proc_uniqueid(current_proc())`, not PID alone. XNU defines the ID as
   incremented on fork/spawn/vfork and stable across exec
   ([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/sys/proc_ro.h#L60-L68)).
2. Match a compiled list of `(parent vnode identity, component name)` pairs.
   Denying `jb` below `/var`, for example, hides the whole `/var/jb` subtree
   without parsing an untrusted full path.
3. Return `ENOENT` only for a currently leased process. All other processes,
   including package managers, `launchd`, and `shadowd`, take the original
   path unchanged.
4. Keep the lease table bounded and remove entries on process death, daemon
   restart, and boot-ID change.

This covers raw `open`, `openat`, `stat`, `access`, and related calls that
route through `namei`. It does not cover already-open file descriptors.

Directory enumeration is a separate seam. `getdirentries_common` performs a
single directory-level MACF check and then lets `VNOP_READDIR` fill the
caller's buffer
([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_syscalls.c#L10286-L10364)).
The MACF readdir callback receives only the credential and directory vnode,
not individual names
([interface](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/security/mac_policy.h#L4437-L4453)).
Consequently lookup denial alone still leaks `jb` from `getdirentries64("/var")`.
A complete backend needs a second, post-VNOP filter for `getdirentries*` and
the bulk-attribute enumeration variants. Until that exists, retain Shadow's
userspace enumeration filters and describe raw enumeration as unsupported.

## Why this cannot be a normal Shadow tweak backend today

On embedded XNU, the MAC policy list and its entries are
`SECURITY_READ_ONLY_LATE` and fixed-size
([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/security/mac_base.c#L240-L258));
late registration cannot grow the list and returns `ENOMEM` when full
([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/security/mac_base.c#L638-L674)).
Directly replacing VFS or MACF function pointers is also not equivalent to
installing a safe hook: vnode operation vectors are shared and invoked as
kernel function pointers
([lookup dispatch](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/kpi_vfs.c#L3367-L3385),
[readdir dispatch](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/kpi_vfs.c#L5300-L5323)).

Dopamine's first-party `libjailbreak` initializes physical kernel access and,
only on supported configurations, kernel calls
([initialization](https://github.com/opa334/Dopamine/blob/335983a8ab3b8bf0225d250ae53d6bd5794c8c66/BaseBin/libjailbreak/src/main.c#L13-L46)).
Its arm64 kernel-call implementation explicitly refuses arm64e and iOS 16+
([source](https://github.com/opa334/Dopamine/blob/335983a8ab3b8bf0225d250ae53d6bd5794c8c66/BaseBin/libjailbreak/src/kcall_arm64.c#L109-L142)).
The repository exposes no supported API for installing a persistent VFS/MACF
callback. Kernel read/write can alter data; it does not create trusted,
executable, correctly authenticated hook code.

Accordingly, implement this only if each supported jailbreak supplies a
documented hook primitive that owns PAC/PPL/KTRR details, or as an upstream
jailbreak/kernelcache patch. Do not ship handwritten patchfinder offsets or
an executable trampoline from `shadowd`.

## Rejected alternatives

| Mechanism | Verdict | Reason |
|---|---|---|
| Global `VISSHADOW` on jailbreak paths | **Reject** | Although `namei` tests the bit generically on `NAMEDSTREAMS` builds, it has no process context. It would also break the jailbreak's own loaders, package managers, and daemons. |
| Shared APFS vnode-op replacement | **Reject** | `v_op` is filesystem-wide, so the hook has global blast radius; it still needs executable kernel code and authenticated function-pointer installation. |
| Syscall-table replacement | **Reject** | Global and incomplete: many path syscalls, `*at` forms, fd operations, and enumeration ABIs must remain consistent. It recreates `namei` badly. |
| Stack a deny-only Seatbelt profile in the app | **No-go for production** | Dopamine exposes sandbox-extension APIs that grant access, but no supported deny-profile stacking API; its own check-in issues read/read-write extensions ([source](https://github.com/opa334/Dopamine/blob/335983a8ab3b8bf0225d250ae53d6bd5794c8c66/BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c#L177-L210)). Applying a private profile to an already sandboxed app risks replacing or tightening unrelated rights. MACF specifies authorization-style `EACCES`/`EPERM` failures, not stock-looking `ENOENT` ([interface](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/security/mac_policy.h#L4374-L4393)). A profile compiler/layout would also be private and OS-dependent. |
| Per-process `chroot` into a bind/nullfs tree | **No-go for production** | XNU's `chroot` does give one process an `fd_rdir`, so missing paths naturally return `ENOENT` ([source](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/vfs/vfs_syscalls.c#L4248-L4307)). But it requires root in the target, must run before useful absolute-path opens, does not revoke existing fds, and needs a nearly complete synthetic iOS root. Nullfs/bindfs mounts are entitlement-gated and system mount objects ([nullfs](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/miscfs/nullfs/null_vfsops.c#L104-L177), [bindfs](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/bsd/miscfs/bindfs/bind_vfsops.c#L104-L168)); Dopamine uses bindfs only for global system protection/fakelib mounts, not per-process namespaces ([source](https://github.com/opa334/Dopamine/blob/335983a8ab3b8bf0225d250ae53d6bd5794c8c66/BaseBin/jbctl/src/internal.m#L35-L92)). The mount layout and chroot itself create new fingerprints and are likely to break app resources. Dopamine exposes no supported target-process chroot primitive. |

## Addition to the implementation plan

1. **Repair the existing XPC lease first.** This is still required for daemon
   health and for hiding Shadow's own artifacts at other layers.
2. **Validate the limited `VISSHADOW` claim.** With a held lease, A/B raw
   `open/stat/access/openat` and `getdirentries64` against the exact allowlist.
   Treat success only as global protection for the small artifact allowlist;
   it does not establish a per-process mechanism for `/var/jb` or other broad
   jailbreak roots.
3. **Run a backend-capability spike.** Inventory the exact supported
   Dopamine/palera1n versions for a first-party persistent kernel-hook API.
   KRW or one-shot kcall alone means **unsupported**.
4. **Only when such an API exists, prototype lookup denial.** Use
   `proc_uniqueid`, a fixed parent-vnode/component allowlist, `ENOENT`, and the
   existing process lease. Fail open on every identity or backend error.
5. **Add enumeration filtering before calling it complete.** Cover
   `readdir`, `getdirentries*`, `getattrlistbulk`, and symlink/relative/`*at`
   paths.
6. **Release gate:** target app sees `ENOENT`; non-target apps and jailbreak
   services remain unchanged; PID reuse, target exit, daemon restart, and
   userspace reboot cleanly remove leases; no panic across the declared
   device/version matrix.

If step 3 fails, stop. The production boundary remains userspace/raw-syscall
interception, and the UI must say that kernel per-process path hiding is not
available on that jailbreak.
