#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "UniversalHooks.h"
#import "../../policy/EnvironmentPolicy.h"
#import "../../policy/PathPolicy.h"
#import "../../policy/ProcessPolicy.h"

#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <limits.h>
#import <sys/mount.h>
#import <sys/event.h>

// Forward declaration: shared post-success csops policy, defined in the
// csops section below (used by the raw SYS_csops dispatch case).
static BOOL shdw_csops_apply_after_success(unsigned int ops, void* useraddr, size_t usersize, const void* caller);

// Forwards an intercepted syscall() call with exact arguments. There is no
// v-syscall, so a va_list can't be forwarded through a variadic `...`: the
// trampoline re-reads the argument list and re-passes it with explicit
// parameters. Only the intercepted numbers reach this function (all of
// them take pointers and/or ints — reading pointer-width slots preserves
// every value); unknown numbers pass through replaced_syscall without any
// vararg read.
//
// The number→shape mapping comes from hooks/RawSyscalls.def (single source
// of truth); each SHADW_RAW_CAT/FWD token has one body below, shared by
// every syscall of that shape (the open-family bodies read the mode arg
// only when O_CREAT is set).
static long (*original_syscall)(int number, ...);

static long shdw_fwd_P1(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1);
}

static long shdw_fwd_P2I(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (int) a2);
}

static long shdw_fwd_EXECVE(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (char *const *) a2, (char *const *) a3);
}

static long shdw_fwd_READLINK(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (char *) a2, (size_t) a3);
}

static long shdw_fwd_OPEN(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    // open only takes a mode when O_CREAT is set.
    if(((int) a2) & O_CREAT) {
        intptr_t a3 = va_arg(args, intptr_t);

        return original_syscall(number, (const char *) a1, (int) a2, (mode_t) a3);
    }

    return original_syscall(number, (const char *) a1, (int) a2);
}

static long shdw_fwd_OPENAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    // openat only takes a mode when O_CREAT is set.
    if(((int) a3) & O_CREAT) {
        intptr_t a4 = va_arg(args, intptr_t);

        return original_syscall(number, (int) a1, (const char *) a2, (int) a3, (mode_t) a4);
    }

    return original_syscall(number, (int) a1, (const char *) a2, (int) a3);
}

static long shdw_fwd_OPENDP(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    if(((int) a2) & O_CREAT) {
        intptr_t a5 = va_arg(args, intptr_t);

        return original_syscall(number, (const char *) a1, (int) a2, (int) a3, (int) a4, (mode_t) a5);
    }

    return original_syscall(number, (const char *) a1, (int) a2, (int) a3, (int) a4);
}

static long shdw_fwd_GETATTRLISTAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (void *) a3, (void *) a4, (size_t) a5, (unsigned long) a6);
}

static long shdw_fwd_FSTATAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (struct stat *) a3, (int) a4);
}

// Gated to match its RawSyscalls.def entry: SYS_mknodat is absent on the
// legacy SDK (iOS 13.7), where the def skips the case and the forwarder
// would otherwise be an unused-function error under -Werror. ATMODE is
// unconditional: linkat-family entries (unlinkat/mkdirat, present since iOS
// 8) use it on every SDK, so it always has callers.
static long shdw_fwd_ATMODE(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (mode_t) a3);
}

#ifdef SYS_mknodat
static long shdw_fwd_ATMODEDEV(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (mode_t) a3, (dev_t) a4);
}
#endif

// Phase 1 mutator shapes: plain (path, int/ids) and fd (fd, value...).
// All unconditional — the SYS_ numbers exist since the 15.6 floor.
static long shdw_fwd_PATH3I(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (uid_t) a2, (gid_t) a3);
}

static long shdw_fwd_PATHMD(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (mode_t) a2, (dev_t) a3);
}

static long shdw_fwd_PATHOFF(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (off_t) a2);
}

static long shdw_fwd_FDOFF(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (off_t) a2);
}

static long shdw_fwd_FDMODE(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (mode_t) a2);
}

static long shdw_fwd_FDUIDGID(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (uid_t) a2, (gid_t) a3);
}

// Phase 2 copy/clone shapes: (path, path, ...) and (dirfd, path, dirfd,
// path, ...) / (fd, dirfd, path, ...). Trailing slots (state/flags) are
// read and forwarded untouched — never inspected.
static long shdw_fwd_PATHPATH(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (const char *) a2, (void *) a3, (uint32_t) a4);
}

static long shdw_fwd_CLONEAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (int) a3, (const char *) a4, (uint32_t) a5);
}

static long shdw_fwd_FDPATH(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (int) a2, (const char *) a3, (uint32_t) a4);
}

// linkat-family shapes (present since iOS 8, unconditional): renameat is the
// 4-arg two-pair form (fd, path, fd, path); symlinkat is (target, fd, linkpath).
static long shdw_fwd_RENAMEAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (int) a3, (const char *) a4);
}

static long shdw_fwd_SYMLINKAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (int) a2, (const char *) a3);
}

static long shdw_fwd_CSOPS(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (pid_t) a1, (unsigned int) a2, (void *) a3, (size_t) a4);
}

static long shdw_fwd_SYSCTL(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);

    return original_syscall(number, (int *) a1, (u_int) a2, (void *) a3, (size_t *) a4, (void *) a5, (size_t) a6);
}

static long shdw_fwd_XATTR4(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (void *) a2, (void *) a3, (size_t) a4);
}

static long shdw_fwd_ACCESSEXT(int number, va_list args) {
    // Real signature: (entries, size_t, results, uid_t) — a binary
    // buffer, NOT a path string. Forward the slots untouched; the
    // inspection in the dispatch deliberately skips this number (CAT_NONE).
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (void *) a1, (size_t) a2, (void *) a3, (uid_t) a4);
}

static long shdw_fwd_PTRACE(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (pid_t) a2, (caddr_t) a3, (int) a4);
}

// Phase 4: kill(pid, sig) — same (pid) inspection as the libc hook.
static long shdw_fwd_KILL(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (pid_t) a1, (int) a2);
}

// kevent(kq, changelist, nchanges, eventlist, nevents, timeout): same slot
// shape as the SYSCTL forwarder (6 pointer-width slots), exact kevent types.
static long shdw_fwd_KEVENT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const struct kevent *) a2, (int) a3, (struct kevent *) a4, (int) a5, (const struct timespec *) a6);
}

// kevent64(kq, changelist, nchanges, eventlist, nevents, flags, timeout):
// 7 slots; the changelist/eventlist elements are struct kevent64_s (SDK
// sys/event.h), never struct kevent. Flags + timeout forward untouched.
static long shdw_fwd_KEVENT64(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);
    intptr_t a7 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const struct kevent64_s *) a2, (int) a3, (struct kevent64_s *) a4, (int) a5, (unsigned int) a6, (const struct timespec *) a7);
}

static long shdw_fwd_GETATTRLIST(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (void *) a2, (void *) a3, (size_t) a4, (unsigned long) a5);
}

static long shdw_fwd_GETXATTR(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (const char *) a2, (void *) a3, (size_t) a4, (u_int32_t) a5, (int) a6);
}

static long shdw_fwd_FGETXATTR(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (void *) a3, (size_t) a4, (u_int32_t) a5, (int) a6);
}

static long shdw_fwd_LISTXATTR(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (char *) a2, (size_t) a3, (int) a4);
}

static long shdw_fwd_FLISTXATTR(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (char *) a2, (size_t) a3, (int) a4);
}

static long shdw_fwd_REMOVEXATTR(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (const char *) a2, (int) a3);
}

static long shdw_fwd_FREMOVEXATTR(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (int) a3);
}

static long shdw_fwd_UTIMES(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (const struct timeval *) a2);
}

static long shdw_fwd_FUTIMES(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const struct timeval *) a2);
}

static long shdw_fwd_LINK(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (const char *) a2);
}

static long shdw_fwd_OPENEXT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);

    return original_syscall(number, (const char *) a1, (int) a2, (uid_t) a3, (gid_t) a4, (int) a5, (void *) a6);
}

static long shdw_fwd_GETDIRENTRIES(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (void *) a2, (size_t) a3, (off_t *) a4);
}

static long shdw_fwd_GETFSSTAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);

    return original_syscall(number, (struct statfs *) a1, (int) a2, (int) a3);
}

// proc_info(callnum, pid, flavor, arg, buffer, buffersize).
static long shdw_fwd_PROCINFO(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);
    intptr_t a5 = va_arg(args, intptr_t);
    intptr_t a6 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (int) a2, (int) a3, (uint64_t) a4, (void *) a5, (int) a6);
}

static long shdw_syscall_forward(int number, va_list args) {
    switch(number) {
#define SHADW_RAWSYSCALL(NUM, ARITY, CAT, FWD) case NUM: return shdw_fwd_##FWD(NUM, args);
#include "RawSyscalls.def"
#undef SHADW_RAWSYSCALL
        default:
            // Unreachable: replaced_syscall only forwards the intercepted
            // set (the def-generated chain at its top). Keep this default
            // as the register passthrough rather than reading unknown
            // arities.
            return original_syscall(number);
    }
}

// Path/process classification shared with libc.x lives in
// policy/PathPolicy.m and policy/ProcessPolicy.m (dirfd-aware *at
// classification, uncached per-pid classification, the kinfo cache and the
// filtered KERN_PROC_ALL enumeration). The raw surface's original calls
// re-enter the (possibly __syscall-delegating) dispatch, so the enumeration
// adapter below runs with the reentrancy guard (reentrant = YES).

// Adapter: the shared KERN_PROC_ALL filter calls the original through a
// sysctl-shaped function pointer; here that is the raw syscall with the
// sysctl MIB arguments.
static int shdw_raw_sysctl_original(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    return (int) original_syscall(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen);
}

// Policy categories for the intercepted set (from hooks/RawSyscalls.def):
// each category maps to one inspection branch in the dispatch below. The
// enum lives in hooks.h (shared with the svc-patch trampoline in
// svc_patch.x).
shdw_raw_syscall_category_t shdw_raw_syscall_category(int number) {
    switch(number) {
#define SHADW_RAWSYSCALL(NUM, ARITY, CAT, FWD) case NUM: return SHADW_RAW_CAT_##CAT;
#include "RawSyscalls.def"
#undef SHADW_RAWSYSCALL
        default:
            return SHADW_RAW_CAT_NONE;
    }
}

// Raw getdirentries64 result filter: compacts restricted entries out of the
// caller's buffer. The kernel packs dirent64 records d_reclen-aligned
// (struct dirent is the dirent64 layout on arm64), so removing an entry
// memmoves the tail down by its d_reclen — record alignment and each
// survivor's d_seekoff stay intact. Returns the adjusted byte count; a
// fully-filtered batch reports 0 (the caller reads it as end-of-directory,
// the same hiding the libc readdir hooks achieve per-entry). The caller's
// *basep is left untouched: it records the offset where the batch STARTED,
// and the next batch resumes where the kernel advanced to, so removed
// entries are simply never revisited. Reachable only from the
// external-caller-gated after-success path in shdw_syscall_dispatch — the
// classification is decided there, never re-read here.
static long shdw_dirents_filtered(char* buf, long count, const char* dir) {
    char joined[PATH_MAX * 2];
    long in = 0;
    long out = 0;

    while(in < count) {
        struct dirent* de = (struct dirent *) (buf + in);

        if(de->d_reclen == 0 || in + de->d_reclen > count) {
            break;  // malformed tail: keep it rather than mis-walk
        }

        int n = snprintf(joined, sizeof(joined), "%s/%s", dir, de->d_name);
        BOOL restricted = shdw_dir_leaf_external_hidden(dir, de->d_name)
            || (n > 0 && n < (int) sizeof(joined)
                && ([_shadow isCPathRestricted:joined] || shdw_path_is_external_hidden(joined)));

        if(!restricted) {
            if(out != in) {
                memmove(buf + out, buf + in, de->d_reclen);
            }

            out += de->d_reclen;
        }

        in += de->d_reclen;
    }

    return out;
}

// Raw getfsstat(64) count-only probe: getfsstat(NULL, 0, flags) reports the
// TOTAL mount count. A libc getfsstat/getmntinfo caller sees the FILTERED
// count, so the raw count-only answer must match — else the two APIs
// contradict (raw sees N mounts, libc sees N-k). Snapshot the full array
// through the raw original, filter with the SAME shared predicate the buffer
// case and the libc wrappers use, return the filtered count. On OOM, fall
// back to the unfiltered count (never crashes; only degrades to the pre-fix
// behavior for that one call).
static long shdw_raw_getfsstat_filtered_count(int number, int flags, long rawCount) {
    if(rawCount <= 0 || rawCount > INT_MAX / (long) sizeof(struct statfs)) {
        return rawCount;
    }

    size_t bytes = (size_t) rawCount * sizeof(struct statfs);
    struct statfs* snapshot = malloc(bytes);

    if(!snapshot) {
        return rawCount;
    }

    long written = original_syscall(number, snapshot, (int) bytes, flags);
    long filtered = rawCount;

    if(written > 0) {
        int cap = (int) (bytes / sizeof(struct statfs));

        if(written > cap) {
            written = cap;
        }

        filtered = shdw_filter_mounts(snapshot, (int) written, YES);
    }

    free(snapshot);
    return filtered;
}

// Post-passthrough dispatch: inspection, policy, forwarding, and
// after-success sanitization for the intercepted set. Shared by the syscall
// and __syscall hooks; called only after the hook's own OR-chain passthrough
// has run.
static long shdw_syscall_dispatch(int number, BOOL ext, va_list args) {
    // Read the decision args from a COPY so the forward trampoline below
    // still sees the full, unadvanced argument list.
    va_list inspect;
    va_copy(inspect, args);

    // Policy args hoisted here, re-used after the forward for after-success
    // sanitization.
    pid_t csops_pid = 0;
    unsigned int csops_ops = 0;
    void* csops_useraddr = NULL;
    size_t csops_usersize = 0;

    int* sysctl_mib = NULL;
    u_int sysctl_miblen = 0;
    void* sysctl_oldp = NULL;
    size_t* sysctl_oldlenp = NULL;
    void* sysctl_newp = NULL;

    // Raw getdirentries64 policy args (hoisted; used after the forward).
    int gd_fd = -1;
    char* gd_buf = NULL;

    // Raw getfsstat(64) policy args (hoisted; used after the forward).
    struct statfs* fs_buf = NULL;
    int fs_capacity = 0;
    int fs_flags = 0;

    // Raw proc_info(2) region-path policy args (hoisted; used after the forward).
    int pi_pid = 0;
    int pi_flavor = 0;
    void* pi_buffer = NULL;
    int pi_buffersize = 0;
    BOOL pi_region_path = NO;
    BOOL pi_vnodepath = NO;

    // Raw statfs64 single-mount policy args.
    const char* sfs_path = NULL;
    struct statfs* sfs_buf = NULL;

    // Caller classification is read at the HOOK SITE (replaced_syscall /
    // replaced___syscall) and threaded in: this dispatch is a real, non-inlined
    // function with two callers, so an isCallerExternal() read HERE would see
    // the trampoline's own (ShadowCore) return address and misclassify every
    // caller as internal. Same explicit-caller shape the svc trampoline uses.
    shdw_raw_syscall_category_t cat = shdw_raw_syscall_category(number);
    // Handle single pathname syscalls. NOTE: SYS_access_extended is NOT
    // inspected — its first argument is a binary entries buffer, not a C
    // string; it is still forwarded with its exact arity below (CAT_NONE).
    // The category switch replaces the per-number membership chains: the
    // number→category mapping is generated from hooks/RawSyscalls.def.
    if(ext) {
        switch(cat) {
            case SHADW_RAW_CAT_CSOPS: {
                csops_pid = (pid_t) va_arg(inspect, intptr_t);
                csops_ops = (unsigned int) va_arg(inspect, intptr_t);
                csops_useraddr = (void *) va_arg(inspect, intptr_t);
                csops_usersize = (size_t) va_arg(inspect, intptr_t);

                // Restricted other pid answers the stock-dead shape (rc=-1
                // ESRCH) — same dead-shape discipline as the kill hook, so a
                // raw csops sweep agrees with the filtered pid lists. Dead
                // pids already fail ESRCH in the kernel; this only converts
                // the live-but-hidden answers. Checked before MARKKILL: a
                // dead pid marks ESRCH, not EBADEXEC.
                if(csops_pid > 0 && csops_pid != getpid() && shdw_pid_is_restricted(csops_pid)) {
                    errno = ESRCH;
                    va_end(inspect);
                    return -1;
                }

                // CS_OPS_MARKKILL on a process other than self: same policy as
                // the csops hook — reject BEFORE the original runs (never
                // execute-then-fail).
                if(csops_ops == CS_OPS_MARKKILL && csops_pid != getpid()) {
                    errno = EBADEXEC;
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_AT: {
                int dirfd = (int) va_arg(inspect, intptr_t);
                const char* pathname = va_arg(inspect, const char *);

                // Same dirfd-aware path policy as the libc.x *at hooks (shared
                // policy/PathPolicy.m).
                if(shdw_at_path_denied(dirfd, pathname)) {
                    va_end(inspect);
                    return -1;  // errno set by the helper
                }
            } break;

            // Phase 1 mutators: plain-path deny ENOENT (rmdir contract),
            // fd variants resolve via F_GETPATH + EBADF (futimes contract),
            // fail open when the fd has no nameable path.
            case SHADW_RAW_CAT_PATH3I:
            case SHADW_RAW_CAT_PATHMD:
            case SHADW_RAW_CAT_PATHOFF: {
                const char* pathname = va_arg(inspect, const char *);

                if(shdw_path_is_external_hidden(pathname) || [_shadow isCPathRestricted:pathname]) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
            } break;

            // Phase 2 copy/clone: BOTH endpoints classified (src exfil or
            // dst materialization). clonefileat resolves each path against
            // its own dirfd (linkat pattern); fclonefileat checks the src
            // fd fresh, dst via dirfd. Deny ENOENT (path contract).
            case SHADW_RAW_CAT_PATHPATH: {
                const char* from = va_arg(inspect, const char *);
                const char* to = va_arg(inspect, const char *);

                if((from && (shdw_path_is_external_hidden(from) || [_shadow isCPathRestricted:from])) ||
                   (to && (shdw_path_is_external_hidden(to) || [_shadow isCPathRestricted:to]))) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_CLONEAT: {
                int srcfd = (int) va_arg(inspect, intptr_t);
                const char* src = va_arg(inspect, const char *);
                int dstfd = (int) va_arg(inspect, intptr_t);
                const char* dst = va_arg(inspect, const char *);

                if(shdw_at_path_denied(srcfd, src) || shdw_at_path_denied(dstfd, dst)) {
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_FDPATH: {
                int srcfd = (int) va_arg(inspect, intptr_t);
                int dstfd = (int) va_arg(inspect, intptr_t);
                const char* dst = va_arg(inspect, const char *);

                if(shdw_fd_path_restricted(srcfd)) {
                    errno = EBADF;
                    va_end(inspect);
                    return -1;
                }

                if(shdw_at_path_denied(dstfd, dst)) {
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_SYMLINKAT: {
                const char* target = va_arg(inspect, const char *);
                int dstfd = (int) va_arg(inspect, intptr_t);
                const char* dst = va_arg(inspect, const char *);

                // Link LOCATION only (dst via dirfd): same single-path AT
                // policy as the libc symlinkat location check (hidden+ruleset,
                // ENOENT). The TARGET needs no raw check: a symlink target need
                // not exist, so hidden-vs-absent targets succeed identically —
                // no natural split to close.
                (void)target;
                if(shdw_at_path_denied(dstfd, dst)) {
                    va_end(inspect);
                    return -1;
                }
            } break;

            // Phase 4: kill liveness probe — ESRCH agrees with the
            // sysctl/libproc filtered lists. Self-signals pass through.
            case SHADW_RAW_CAT_KILL: {
                pid_t pid = (pid_t) va_arg(inspect, intptr_t);

                if(pid > 0 && pid != getpid() && shdw_pid_is_restricted(pid)) {
                    errno = ESRCH;
                    va_end(inspect);
                    return -1;
                }
            } break;

            // Raw kevent(kq, changelist, nchanges, ...): same EVFILT_PROC-only
            // inspection as the libc kevent hook — a raw syscall(SYS_kevent)
            // must not see a daemon the wrapper reports dead. Other filters
            // pass through untouched.
            case SHADW_RAW_CAT_KEVENT: {
                (void) va_arg(inspect, intptr_t);  // kq
                const struct kevent* changelist = (const struct kevent *) va_arg(inspect, intptr_t);
                int nchanges = (int) va_arg(inspect, intptr_t);

                if(changelist && nchanges > 0) {
                    pid_t self = getpid();

                    for(int i = 0; i < nchanges; i++) {
                        if(changelist[i].filter == EVFILT_PROC) {
                            pid_t pid = (pid_t) changelist[i].ident;

                            if(pid > 0 && pid != self && shdw_pid_is_restricted(pid)) {
                                errno = ESRCH;
                                va_end(inspect);
                                return -1;
                            }
                        }
                    }
                }
            } break;

            // Raw kevent64: same EVFILT_PROC-only inspection as KEVENT, with
            // the 64-bit changelist type (struct kevent64_s — filter is still
            // the s16 at offset 8, ident the u64 at offset 0, SDK sys/event.h).
            // Delete-after-ok parity: EV_DELETE entries are denied the same
            // way, exactly like the kevent path (the denied ADD registers
            // nothing, so there is nothing to delete).
            case SHADW_RAW_CAT_KEVENT64: {
                (void) va_arg(inspect, intptr_t);  // kq
                const struct kevent64_s* changelist64 = (const struct kevent64_s *) va_arg(inspect, intptr_t);
                int nchanges64 = (int) va_arg(inspect, intptr_t);

                if(changelist64 && nchanges64 > 0) {
                    pid_t self = getpid();

                    for(int i = 0; i < nchanges64; i++) {
                        if(changelist64[i].filter == EVFILT_PROC) {
                            pid_t pid = (pid_t) changelist64[i].ident;

                            if(pid > 0 && pid != self && shdw_pid_is_restricted(pid)) {
                                errno = ESRCH;
                                va_end(inspect);
                                return -1;
                            }
                        }
                    }
                }
            } break;

            case SHADW_RAW_CAT_FDOFF:
            case SHADW_RAW_CAT_FDMODE:
            case SHADW_RAW_CAT_FDUIDGID: {
                int fd = (int) va_arg(inspect, intptr_t);

                if(shdw_fd_path_restricted(fd)) {
                    errno = EBADF;
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_SYSCTL: {
                sysctl_mib = (int *) va_arg(inspect, intptr_t);
                sysctl_miblen = (u_int) va_arg(inspect, intptr_t);
                sysctl_oldp = (void *) va_arg(inspect, intptr_t);
                sysctl_oldlenp = (size_t *) va_arg(inspect, intptr_t);
                sysctl_newp = (void *) va_arg(inspect, intptr_t);

                shdw_proc_mib_kind_t kind = shdw_proc_mib_kind(sysctl_mib, sysctl_miblen);

                // kern.bootargs: answered directly (empty string, stock
                // semantics) — see shdw_bootargs_filtered. Setting boot args
                // (newp) passes through.
                if(kind == SHADW_PROC_MIB_BOOTARGS && sysctl_newp == NULL) {
                    int ba_ret = shdw_bootargs_filtered(sysctl_oldp, sysctl_oldlenp);
                    va_end(inspect);
                    return ba_ret;
                }

                // KERN_PROC_ALL process enumeration: same filtered-list policy
                // as the libc.x sysctl hook, via the shared filter
                // (policy/ProcessPolicy.m). The own reentrancy guard keeps a
                // nested (__syscall-delegating) dispatch from re-applying it.
                if(kind == SHADW_PROC_MIB_ALL) {
                    if(!shdw_proc_all_in_progress()) {
                        int proc_ret = shdw_proc_all_filtered(shdw_raw_sysctl_original, sysctl_oldp, sysctl_oldlenp, YES);
                        va_end(inspect);
                        return proc_ret;
                    }
                }

                // Per-pid query of a filtered daemon answers the stock dead
                // shape (rc=0, *oldlenp=0): stock never errors here. The own
                // pid passes — its record is sanitized after success below.
                if(kind == SHADW_PROC_MIB_PID_OTHER && shdw_pid_restricted_uncached(sysctl_mib[3])) {
                    if(!sysctl_oldlenp) {
                        errno = EFAULT;
                        va_end(inspect);
                        return -1;
                    }
                    *sysctl_oldlenp = 0;
                    va_end(inspect);
                    return 0;
                }

                // KERN_PROCARGS(2) is a direct CTL_KERN child: {CTL_KERN, KERN_PROCARGS(2), pid}.
                if((kind == SHADW_PROC_MIB_ARGS2_OTHER || kind == SHADW_PROC_MIB_ARGS_OTHER) && shdw_pid_restricted_uncached(sysctl_mib[2])) {
                    errno = (kind == SHADW_PROC_MIB_ARGS2_OTHER) ? EINVAL : ENOENT;
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_DIRENT:
                // Raw readdir-style enumeration bypasses the libc readdir hooks;
                // the buffer is filtered after success instead. Hoist fd/buf;
                // the dir path is resolved (F_GETPATH) only if the call succeeds.
                gd_fd = (int) va_arg(inspect, intptr_t);
                gd_buf = (char *) va_arg(inspect, intptr_t);
                break;

            case SHADW_RAW_CAT_GETFSSTAT:
                // Raw getfsstat(64) bypasses the libc getfsstat/getmntinfo
                // mount filter; the returned struct statfs array is compacted
                // after success instead. Hoist buf + record capacity (a NULL
                // buf / count-only probe carries no array to filter).
                fs_buf = (struct statfs *) va_arg(inspect, intptr_t);
                fs_capacity = (int) va_arg(inspect, intptr_t) / (int) sizeof(struct statfs);
                fs_flags = (int) va_arg(inspect, intptr_t);
                break;

            case SHADW_RAW_CAT_PROCINFO: {
                // proc_info(callnum, pid, flavor, arg, buffer, buffersize).
                // Only the PIDINFO multiplexer's region-path flavors, for the
                // own pid, carry an injected backing path; everything else
                // forwards untouched. Hoist for the after-success reshape.
                int callnum = (int) va_arg(inspect, intptr_t);
                pi_pid = (int) va_arg(inspect, intptr_t);
                pi_flavor = (int) va_arg(inspect, intptr_t);
                (void) va_arg(inspect, intptr_t);  // arg (region address)
                pi_buffer = (void *) va_arg(inspect, intptr_t);
                pi_buffersize = (int) va_arg(inspect, intptr_t);

                // A restricted OTHER pid's per-pid inspection is denied the same
                // way a dead pid answers (raw shape -1, ESRCH).
                if(callnum == SHADOW_PROC_INFO_CALL_PIDINFO
                   && pi_pid > 0 && pi_pid != getpid()
                   && shdw_pid_is_restricted(pi_pid)) {
                    errno = ESRCH;
                    va_end(inspect);
                    return -1;
                }

                pi_region_path = (callnum == SHADOW_PROC_INFO_CALL_PIDINFO
                    && pi_pid == getpid()
                    && (pi_flavor == SHADOW_PROC_PIDREGIONPATHINFO
                        || pi_flavor == SHADOW_PROC_PIDREGIONPATHINFO2
                        || pi_flavor == SHADOW_PROC_PIDREGIONPATHINFO3
                        || pi_flavor == SHADOW_PROC_PIDREGIONPATH));

                // Own cwd/root vnode paths (flavor 9): same shared reshape
                // the libc proc_pidinfo hook applies.
                pi_vnodepath = (callnum == SHADOW_PROC_INFO_CALL_PIDINFO
                    && pi_pid == getpid()
                    && pi_flavor == SHADOW_PROC_PIDVNODEPATHINFO);
            } break;

            case SHADW_RAW_CAT_FDXATTR: {
                int fd = (int) va_arg(inspect, intptr_t);

                // Same fd policy as the libc.x fgetxattr/flistxattr hooks:
                // resolve fresh, fail open when the path can't be named (the
                // descriptor is legitimate — tty/pipe/socket).
                if(shdw_fd_path_restricted(fd)) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
            } break;

#ifdef SYS_freadlink
            case SHADW_RAW_CAT_FREADLINK: {
                // Raw freadlink(fd): same fd policy as the libc.x
                // freadlink hook — fail open when the fd has no nameable
                // path. Number present from the 15.6 floor; the libc
                // declaration is iOS 16+.
                int fd = (int) va_arg(inspect, intptr_t);

                if(shdw_fd_path_restricted(fd)) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
            } break;
#endif

            case SHADW_RAW_CAT_PATH: {
                const char* pathname = va_arg(inspect, const char *);

                // Same predicate PAIR the libc path hooks apply: the ruleset
                // AND the external-hidden set, so a raw open/stat/lstat/access
                // cannot see an object the libc wrappers report absent.
                if(shdw_path_is_external_hidden(pathname) || [_shadow isCPathRestricted:pathname]) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_STATFS: {
                const char* pathname = va_arg(inspect, const char *);
                struct statfs* buf = va_arg(inspect, struct statfs *);

                if(shdw_path_is_external_hidden(pathname) || [_shadow isCPathRestricted:pathname]) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
                sfs_path = pathname;
                sfs_buf = buf;
            } break;

            case SHADW_RAW_CAT_NONE:
            case SHADW_RAW_CAT_PTRACE:
                break;
        }
    }

    // Handle ptrace (anti debug)
    if(cat == SHADW_RAW_CAT_PTRACE) {
        int _request = va_arg(inspect, int);

        if(_request == PT_DENY_ATTACH) {
            va_end(inspect);
            return 0;
        }
    }

    va_end(inspect);

    long result = shdw_syscall_forward(number, args);

    // After-success policies — same as the typed hooks, only on valid
    // success and only for app-origin callers.
    if(ext) {
        switch(cat) {
            case SHADW_RAW_CAT_CSOPS:
                if(result == 0 && csops_pid == getpid() && shdw_csops_apply_after_success(csops_ops, csops_useraddr, csops_usersize, NULL)) {
                    return -1;
                }
                break;

            case SHADW_RAW_CAT_SYSCTL:
                if(result == 0 && sysctl_mib) {
                    shdw_proc_mib_kind_t kind = shdw_proc_mib_kind(sysctl_mib, sysctl_miblen);

                    if(kind == SHADW_PROC_MIB_PID_SELF && sysctl_oldp && sysctl_oldlenp && *sysctl_oldlenp >= sizeof(struct kinfo_proc)) {
                        // Full self-record sanitize: trace flags AND e_ppid=1,
                        // matching the libc per-pid hook (libc_antidebugging.x)
                        // and the KERN_PROC_ALL list filter. A detector reading
                        // its own parent via the RAW syscall must see the same 1
                        // that getppid()/proc_pidinfo/libc sysctl report — else
                        // the raw path is a cross-API contradiction (real parent
                        // here, 1 everywhere else). The sanitizer is a plain
                        // struct-field write under the identical buffer guard, so
                        // there is no reentrancy/safety cost the trace-only path
                        // was avoiding.
                        shdw_proc_sanitize_self_record((struct kinfo_proc *) sysctl_oldp);
                    }

                    // Own KERN_PROCARGS(2): rebuild the raw payload to agree with the
                    // filtered NSProcessInfo/getenv views.
                    if((kind == SHADW_PROC_MIB_ARGS2_SELF || kind == SHADW_PROC_MIB_ARGS_SELF) && sysctl_oldp && sysctl_oldlenp && *sysctl_oldlenp > (size_t) sizeof(int)) {
                        shdw_procargs2_filter(sysctl_oldp, sysctl_oldlenp);
                    }
                }
                break;

            case SHADW_RAW_CAT_DIRENT: {
                // Raw getdirentries64: compact restricted entries out of the
                // result buffer (after success, external callers only). An fd
                // whose path cannot be resolved passes through unfiltered —
                // fail-open, the libc readdir path still filters.
                if(result > 0 && gd_buf) {
                    char dir[PATH_MAX];

                    if(fcntl(gd_fd, F_GETPATH, dir) != -1) {
                        result = shdw_dirents_filtered(gd_buf, result, dir);
                    }
                }
            } break;

            case SHADW_RAW_CAT_GETFSSTAT:
                // Raw getfsstat(64): compact hidden mounts out of the returned
                // struct statfs array (buffer case) or correct the reported
                // count (NULL-buffer count probe) so raw and libc agree. The
                // buffer case filters in place with the SAME shared predicate
                // (shdw_filter_mounts) the libc wrappers use; the count probe
                // re-snapshots and filters to return the same filtered count.
                if(result > 0) {
                    if(fs_buf && fs_capacity > 0) {
                        int written = (int) result;

                        if(written > fs_capacity) {
                            written = fs_capacity;
                        }

                        result = shdw_filter_mounts(fs_buf, written, YES);
                    } else if(!fs_buf) {
                        result = shdw_raw_getfsstat_filtered_count(number, fs_flags, result);
                    }
                }
                break;

            case SHADW_RAW_CAT_PROCINFO:
                // Raw proc_info(2) bypasses the libc proc_pidinfo hook; reshape
                // a hidden image's own-map region into an anonymous (un-named)
                // region via the SAME shared predicate the libc hook uses, so
                // the two views agree. Flavor 9 (own cwd/root vnode paths)
                // gets the same shared container-shape reshape.
                if(result > 0 && pi_region_path) {
                    shdw_region_path_result_sanitize(pi_flavor, pi_buffer, pi_buffersize);
                }
                if(result > 0 && pi_vnodepath) {
                    shdw_vnodepath_result_sanitize(pi_buffer, pi_buffersize);
                }
                break;

            case SHADW_RAW_CAT_STATFS: {
                if(result == 0 && sfs_buf && sfs_path) {
                    if(shdw_filter_mounts(sfs_buf, 1, YES) == 0) {
                        if(shdw_path_under_system_bind_root(sfs_path)) {
                            struct statfs root;
                            memset(&root, 0, sizeof(root));
                            if(original_syscall(SYS_statfs64, "/", &root) == 0) {
                                strlcpy(sfs_buf->f_mntonname, root.f_mntonname, sizeof(sfs_buf->f_mntonname));
                                strlcpy(sfs_buf->f_mntfromname, root.f_mntfromname, sizeof(sfs_buf->f_mntfromname));
                                strlcpy(sfs_buf->f_fstypename, root.f_fstypename, sizeof(sfs_buf->f_fstypename));
                                sfs_buf->f_fssubtype = root.f_fssubtype;
                            } else {
                                errno = ENOENT;
                                return -1;
                            }
                        } else {
                            errno = ENOENT;
                            return -1;
                        }
                    }
                }
            } break;

            case SHADW_RAW_CAT_NONE:
            case SHADW_RAW_CAT_PATH:
            case SHADW_RAW_CAT_PATH3I:
            case SHADW_RAW_CAT_PATHMD:
            case SHADW_RAW_CAT_PATHOFF:
            case SHADW_RAW_CAT_PATHPATH:
            case SHADW_RAW_CAT_CLONEAT:
            case SHADW_RAW_CAT_FDPATH:
            case SHADW_RAW_CAT_SYMLINKAT:
            case SHADW_RAW_CAT_KILL:
            case SHADW_RAW_CAT_KEVENT:
            case SHADW_RAW_CAT_KEVENT64:
            case SHADW_RAW_CAT_FDOFF:
            case SHADW_RAW_CAT_FDMODE:
            case SHADW_RAW_CAT_FDUIDGID:
            case SHADW_RAW_CAT_AT:
            case SHADW_RAW_CAT_FDXATTR:
#ifdef SYS_freadlink
            case SHADW_RAW_CAT_FREADLINK:
#endif
            case SHADW_RAW_CAT_PTRACE:
                break;
        }
    }

    return result;
}

static long replaced_syscall(int number, ...) {
    // Non-intercepted numbers pass through WITHOUT reading any vararg
    // (reading absent varargs is UB). Apple's syscall(2) is a
    // register-passing wrapper: the caller's argument registers are still
    // live at our entry and the trampoline leaves them untouched, so a
    // zero-argument forward is exact. This requires the passthrough to be
    // the first thing this function does — no calls (NSLog,
    // isCallerExternal, ...) may run first, since they clobber x1-x7 — and
    // the intercept test below must stay an OR-chain of compares on
    // `number` (clang lowers it to cmp/branch only; do not turn it into a
    // helper function or switch table). The chain is generated from
    // hooks/RawSyscalls.def — still a plain OR-chain of compares on
    // `number` (clang folds the trailing constant-true operand away and
    // lowers the rest to cmp/branch only).
    if(
#define SHADW_RAWSYSCALL(NUM, ARITY, CAT, FWD) number != NUM &&
#include "RawSyscalls.def"
#undef SHADW_RAWSYSCALL
    1) {
        return original_syscall(number);
    }

    // Read the caller classification HERE (real hook frame) — the dispatch is
    // a separate non-inlined function, so it cannot read the return address
    // itself. Safe now: the passthrough OR-chain above already ran, so the
    // argument registers the zero-arg forward relied on are no longer needed.
    BOOL ext = isCallerExternal();

    va_list args;
    va_start(args, number);
    long result = shdw_syscall_dispatch(number, ext, args);
    va_end(args);

    return result;
}

// __syscall is libsystem_kernel's twin of syscall(2): same register-passing
// convention and (number, ...) shape. Hooked with the same dispatcher.
// Runtime-resolved; skipped cleanly when absent.
static long (*original___syscall)(int number, ...);
static long replaced___syscall(int number, ...) {
    // Same def-generated passthrough chain as replaced_syscall: it must
    // remain the first thing this function does, as a chain of compares on
    // `number` (no helper calls — they would clobber the argument
    // registers the zero-argument forward relies on).
    if(
#define SHADW_RAWSYSCALL(NUM, ARITY, CAT, FWD) number != NUM &&
#include "RawSyscalls.def"
#undef SHADW_RAWSYSCALL
    1) {
        return original___syscall(number);
    }

    BOOL ext = isCallerExternal();

    va_list args;
    va_start(args, number);
    long result = shdw_syscall_dispatch(number, ext, args);
    va_end(args);

    return result;
}

// CS_DEBUGGED (0x10000000) is absent from the vendored codesign.h snapshot;
// define it here so the sanitizer normalizes that status bit.
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000
#endif

// Sanitizes the status word a successful CS_OPS_STATUS call wrote into the
// caller's buffer: clears jailbreak/debug/platform flags ONLY. Unknown bits
// are preserved and no flag is ever SET — the old code faked CS_JIT_ALLOW |
// CS_REQUIRE_LV, capabilities a stock binary lacks (a fingerprint), and
// contradicting the real signing state. App-set anti-tamper flags
// (CS_HARD/CS_KILL/CS_RESTRICT/CS_ENFORCEMENT/CS_REQUIRE_LV) are left alone:
// clearing them would weaken the app's own protection and deviate from stock.
static void shdw_csops_sanitize_status(uint32_t* flags) {
    *flags &= ~CS_PLATFORM_BINARY;
    *flags &= ~CS_PLATFORM_PATH;
    *flags &= ~CS_GET_TASK_ALLOW;
    *flags &= ~CS_INSTALLER;
    *flags &= ~CS_ENTITLEMENTS_VALIDATED;
    *flags &= ~CS_DEBUGGED;

    // Aggressive only: a store-distributed app carries the kernel-set
    // anti-tamper pair CS_HARD|CS_KILL (the App Store signature enables "kill
    // if invalid"); a development/ad-hoc-signed binary — like an injected test
    // process — lacks them. A probe that treats the ABSENCE of CS_HARD/CS_KILL
    // as evidence (roothider's mislabelled "jit-allow" = !(CS_HARD|CS_KILL))
    // then flags the process. Set them to complete the store-app appearance.
    // Natural mode leaves the real signing shape untouched (no fabricated
    // capabilities), so this only runs when the user opts in.
    if(shdw_detector_aggressive) {
        *flags |= (CS_HARD | CS_KILL);
    }
}

// Shared post-success csops policy, applied only after the original call
// SUCCEEDED (on a failed call the kernel wrote no status/hash, and a
// synthetic EBADEXEC on top of a real error would deviate from stock):
// CS_OPS_STATUS gets the clear-only sanitization at *useraddr (the flags are
// written into the CALLER's buffer, not returned — editing `ret` would
// corrupt the return value); CS_OPS_CDHASH is hidden. `caller` is the hook
// replacement's return address (NULL on the raw-syscall dispatch path, which
// keeps the strict policy). Returns YES when the call must be converted into
// a denial (errno set), NO to pass through.
static BOOL shdw_csops_apply_after_success(unsigned int ops, void* useraddr, size_t usersize, const void* caller) {
    if(ops == CS_OPS_STATUS && useraddr) {
        // CS_OPS_STATUS always writes a 4-byte status word on success,
        // regardless of the `usersize` the caller declared: passing
        // usersize=0 (as some probes deliberately do to slip past a naive
        // `usersize >= 4` guard) does NOT stop the kernel from filling the
        // word, so the sanitiser must run whenever the kernel actually wrote
        // it. Guard only on a real success having occurred (checked by the
        // callers before invoking this) and a non-NULL destination.
        (void)usersize;
        shdw_csops_sanitize_status((uint32_t *) useraddr);
        return NO;
    }

    if(ops == CS_OPS_CDHASH) {
        // Hide CDHASH for trustcache checks — EXCEPT when the caller IS
        // Security.framework: its self-identity construction
        // (SecCodeCopySelf) reads the CDHASH through csops, and blinding
        // THAT degrades Security's answer to "unsigned" (-67065), a worse
        // leak than the hash itself (an unsigned main executable is direct
        // tamper evidence). Detectors calling csops directly remain blinded.
        if(!caller || !shdw_addr_in_security_framework(caller)) {
            errno = EBADEXEC;
            return YES;
        }

        return NO;
    }

    return NO;
}

static int (*original_csops)(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
static int replaced_csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
    BOOL ext = isCallerExternal();

    if(ext) {
        // Restricted other pid answers the stock-dead shape (rc=-1 ESRCH) —
        // same dead-shape discipline as the kill hook, so a per-pid csops
        // sweep agrees with the filtered pid lists. Checked before MARKKILL:
        // a dead pid marks ESRCH, not EBADEXEC.
        if(pid > 0 && pid != getpid() && shdw_pid_is_restricted(pid)) {
            errno = ESRCH;
            return -1;
        }

        // CS_OPS_MARKKILL on a process other than self is jailbreak-style
        // marking (stock apps only ever mark THEMSELVES for kill). Reject
        // BEFORE the original runs — executing the mark and then failing
        // is the execute-then-fail fingerprint. Self-marks are legitimate
        // app anti-tamper and pass through untouched.
        if(ops == CS_OPS_MARKKILL && pid != getpid()) {
            errno = EBADEXEC;
            return -1;
        }
    }

    int ret = original_csops(pid, ops, useraddr, usersize);

    if(ext && pid == getpid() && ret == 0 && shdw_csops_apply_after_success(ops, useraddr, usersize, __builtin_return_address(0))) {
        return -1;
    }

    return ret;
}

// csops_audittoken: same policy as csops (MARKKILL pre-reject, status
// clear-only and CDHASH hiding after success). The audit token is passed
// through untouched — the policy keys on the pid, and the token is how the
// kernel identifies the target.
static int (*original_csops_audittoken)(pid_t pid, unsigned int ops, void* useraddr, size_t usersize, audit_token_t* token);
static int replaced_csops_audittoken(pid_t pid, unsigned int ops, void* useraddr, size_t usersize, audit_token_t* token) {
    BOOL ext = isCallerExternal();

    if(ext && pid > 0 && pid != getpid() && shdw_pid_is_restricted(pid)) {
        errno = ESRCH;
        return -1;
    }

    if(ext && ops == CS_OPS_MARKKILL && pid != getpid()) {
        errno = EBADEXEC;
        return -1;
    }

    int ret = original_csops_audittoken(pid, ops, useraddr, usersize, token);

    if(ext && ret == 0 && pid == getpid() && shdw_csops_apply_after_success(ops, useraddr, usersize, __builtin_return_address(0))) {
        return -1;
    }

    return ret;
}

// --- sysctlbyname/__sysctlbyname: kern.proc.* routed through the same
// filtering as the sysctl hooks, via the shared policy
// (policy/ProcessPolicy.m): "kern.proc.all" answers the filtered process
// list (same two-phase enumeration), and a KERN_PROC_PID query for self has
// its tracing flags cleared after a successful original call. ---

static int shdw_sysctlbyname_policy(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen, int (*original)(const char*, void*, size_t*, void*, size_t)) {
    if(isCallerExternal() && name) {
        // kern.bootargs: answered directly (empty string, stock semantics)
        // — see shdw_bootargs_filtered. Setting boot args (newp) passes
        // through.
        if(strcmp(name, "kern.bootargs") == 0 && newp == NULL) {
            return shdw_bootargs_filtered(oldp, oldlenp);
        }

        if(strcmp(name, "kern.proc.all") == 0) {
            // The original calls below re-enter the (possibly
            // __syscall-delegating) dispatch, hence reentrant = YES.
            return shdw_proc_all_filtered(shdw_raw_sysctl_original, oldp, oldlenp, YES);
        }

        static const char procPidPrefix[] = "kern.proc.pid.";

        if(strncmp(name, procPidPrefix, sizeof(procPidPrefix) - 1) == 0) {
            pid_t pid = (pid_t) atoi(name + sizeof(procPidPrefix) - 1);

            if(pid != getpid()) {
                // Same dead shape as the MIB path: stock never errors here.
                if(shdw_pid_restricted_uncached(pid)) {
                    if(!oldlenp) {
                        errno = EFAULT;
                        return -1;
                    }
                    *oldlenp = 0;
                    return 0;
                }

                return original(name, oldp, oldlenp, newp, newlen);
            }

            int ret = original(name, oldp, oldlenp, newp, newlen);

            // Remove trace flags from our own process record — only on
            // valid success and only when the buffer carries the record.
            if(ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                shdw_proc_sanitize_self_record((struct kinfo_proc *) oldp);
            }

            return ret;
        }

        static const char procargsPrefix[] = "kern.procargs";

        // "kern.procargs" is a PREFIX of "kern.procargs2.": match the
        // "kern.procargs2." form first, then the legacy "kern.procargs."
        // form (exact-prefix + pid digits, so one can't shadow the other).
        static const char procargs2Prefix[] = "kern.procargs2.";

        if(strncmp(name, procargs2Prefix, sizeof(procargs2Prefix) - 1) == 0) {
            pid_t pid = (pid_t) atoi(name + sizeof(procargs2Prefix) - 1);

            if(pid != getpid()) {
                if(shdw_pid_restricted_uncached(pid)) {
                    errno = ENOENT;
                    return -1;
                }

                return original(name, oldp, oldlenp, newp, newlen);
            }

            int ret = original(name, oldp, oldlenp, newp, newlen);

            // Own payload: rebuild to agree with the filtered argv/env views.
            if(ret == 0 && oldp && oldlenp && *oldlenp > (size_t) sizeof(int)) {
                shdw_procargs2_filter(oldp, oldlenp);
            }

            return ret;
        }

        if(strncmp(name, procargsPrefix, sizeof(procargsPrefix) - 1) == 0
        && name[sizeof(procargsPrefix) - 1] == '.') {
            pid_t pid = (pid_t) atoi(name + sizeof(procargsPrefix));

            if(pid != getpid()) {
                if(shdw_pid_restricted_uncached(pid)) {
                    errno = ENOENT;
                    return -1;
                }

                return original(name, oldp, oldlenp, newp, newlen);
            }

            int ret = original(name, oldp, oldlenp, newp, newlen);

            if(ret == 0 && oldp && oldlenp && *oldlenp > (size_t) sizeof(int)) {
                shdw_procargs2_filter(oldp, oldlenp);
            }

            return ret;
        }
    }

    return original(name, oldp, oldlenp, newp, newlen);
}

static int (*original_sysctlbyname)(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
static int replaced_sysctlbyname(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    return shdw_sysctlbyname_policy(name, oldp, oldlenp, newp, newlen, original_sysctlbyname);
}

static int (*original___sysctlbyname)(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen);
static int replaced___sysctlbyname(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    return shdw_sysctlbyname_policy(name, oldp, oldlenp, newp, newlen, original___sysctlbyname);
}

// --- _NSGetEnviron: returns the ADDRESS of the caller's environ variable.
// Hooked to return a pointer to OUR OWN filtered snapshot — libc's environ
// pointer is never modified (callers may write through the returned
// pointer; ours is private storage). The snapshot is rebuilt on every call
// so variables added by setenv since the last call stay visible.
// The filtering itself lives in policy/EnvironmentPolicy.m and mirrors the
// libc envvar group's getenv policy EXACTLY (all DYLD_*/JAILBREAKD_*
// variables, the safe-mode flags, and jailbreak PATH components): a scan of
// *environ must agree with getenv() and NSProcessInfo.environment, or a
// detector comparing the two channels sees the contradiction.
// Direct reads of the raw `environ` data symbol ARE covered: external
// importers' `environ` slot is rebound (below, in shdw_universal_syscall) to
// a Shadow-owned cell pointing at a filtered copy of the array. This hook
// still handles the _NSGetEnviron() function channel; the two agree because
// both consult the same EnvironmentPolicy filter.

extern char*** _NSGetEnviron(void);

static char*** (*original_NSGetEnviron)(void);
static char*** replaced_NSGetEnviron(void) {
    if(!isCallerExternal()) {
        return original_NSGetEnviron();
    }

    // Filter the REAL array: the `environ` symbol is rebound process-wide to
    // Shadow's filtered copy, so reading it here would double-filter (harmless
    // but wasteful). shdw_env_real() is the true source.
    char*** snapshot = shdw_env_filtered_snapshot(shdw_env_real());

    return snapshot ? snapshot : original_NSGetEnviron();
}

// syscall/__syscall/csops are hooked on a REBIND-ONLY lane, not `hooks`.
void shdw_universal_syscall(SHDWHookSession* hooks) {
    [hooks hookRebindSymbol:@"syscall" withReplacement:replaced_syscall outOldPtr:(void **) &original_syscall];
    [hooks hookRebindSymbol:@"csops" withReplacement:replaced_csops outOldPtr:(void **) &original_csops];

    // Runtime-resolve __syscall; skipped cleanly when absent.
    void* sym___syscall = shdw_resolve_libsystem("___syscall");
    // Some iOS builds export syscall and __syscall as the same entry point.
    // Address-based rebinders already cover every slot for that address; a
    // second replacement cannot coexist and only reports a false failure.
    if(sym___syscall && sym___syscall != (void *)syscall) {
        [hooks hookRebindSymbol:@"___syscall" withReplacement:replaced___syscall outOldPtr:(void **) &original___syscall];
    }

    // Misc sibling surfaces: runtime-resolved, skipped cleanly when absent.
    void* sym_misc = shdw_resolve_libsystem("_sysctlbyname");
    if(sym_misc) {
        [hooks hookRebindSymbol:@"_sysctlbyname" withReplacement:replaced_sysctlbyname outOldPtr:(void **) &original_sysctlbyname];
    }

    sym_misc = shdw_resolve_libsystem("___sysctlbyname");
    if(sym_misc) {
        [hooks hookRebindSymbol:@"___sysctlbyname" withReplacement:replaced___sysctlbyname outOldPtr:(void **) &original___sysctlbyname];
    }

    sym_misc = shdw_resolve_libsystem("_csops_audittoken");
    if(sym_misc) {
        [hooks hookRebindSymbol:@"_csops_audittoken" withReplacement:replaced_csops_audittoken outOldPtr:(void **) &original_csops_audittoken];
    }

    sym_misc = shdw_resolve_libsystem("_NSGetEnviron");
    if(sym_misc) {
        [hooks hookRebindSymbol:@"_NSGetEnviron" withReplacement:replaced_NSGetEnviron outOldPtr:(void **) &original_NSGetEnviron];
    }

    // Raw `environ` data-symbol rebind: capture the real cell (&environ) via
    // the unhooked _NSGetEnviron() and publish the first filtered generation
    // BEFORE rebinding, so an importer's slot only ever resolves to a
    // fully-built filtered array. The slot is rebound to
    // &shdw_env_published_array — dereferencing it yields the filtered char**,
    // exactly environ's shape. The rebind is process-wide (ShadowCore's own
    // slot included), so Shadow's own code that needs the TRUE array (child
    // spawns propagating DYLD_INSERT_LIBRARIES to systemhook) reads
    // shdw_env_real() rather than `environ` (see sandbox.x exec family).
    // Late-loaded detector images get the same rebind via the RebindRepair
    // spec journal replay.
    shdw_env_capture_real_environ(_NSGetEnviron());
    [hooks hookRebindSymbol:@"environ"
            withReplacement:(void*)&shdw_env_published_array
                   outOldPtr:NULL];

    // Raw svc #0x80 interception (svc_patch.x): loaded-image writes are
    // serialized and stop-the-world before app code can execute them.
    shdw_svc_patch_install();
}
