#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"
#import "../../policy/EnvironmentPolicy.h"
#import "../../policy/PathPolicy.h"
#import "../../policy/ProcessPolicy.h"

#import <unistd.h>

// Forward declaration: shared post-success csops policy, defined in the
// csops section below (used by the raw SYS_csops dispatch case).
static BOOL shdw_csops_apply_after_success(unsigned int ops, void* useraddr, size_t usersize);

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

    // openat only takes a mode when O_CREAT is set.
    if(((int) a2) & O_CREAT) {
        intptr_t a3 = va_arg(args, intptr_t);

        return original_syscall(number, (int) a1, (const char *) a2, (mode_t) a3);
    }

    return original_syscall(number, (int) a1, (const char *) a2);
}

static long shdw_fwd_FSTATAT(int number, va_list args) {
    intptr_t a1 = va_arg(args, intptr_t);
    intptr_t a2 = va_arg(args, intptr_t);
    intptr_t a3 = va_arg(args, intptr_t);
    intptr_t a4 = va_arg(args, intptr_t);

    return original_syscall(number, (int) a1, (const char *) a2, (struct stat *) a3, (int) a4);
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
        BOOL restricted = n > 0 && n < (int) sizeof(joined) && [_shadow isCPathRestricted:joined];

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

// Post-passthrough dispatch: inspection, policy, forwarding, and
// after-success sanitization for the intercepted set. Shared by the syscall
// and __syscall hooks; called only after the hook's own OR-chain passthrough
// has run.
static long shdw_syscall_dispatch(int number, va_list args) {
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

    // Raw getdirentries64 policy args (hoisted; used after the forward).
    int gd_fd = -1;
    char* gd_buf = NULL;

    // Caller classification hoisted: the return-address read happens once,
    // inline, at this entry (same frame for both gates below). The policy
    // category (from hooks/RawSyscalls.def) is computed once and drives
    // every branch below.
    BOOL ext = isCallerExternal();
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

            case SHADW_RAW_CAT_SYSCTL: {
                sysctl_mib = (int *) va_arg(inspect, intptr_t);
                sysctl_miblen = (u_int) va_arg(inspect, intptr_t);
                sysctl_oldp = (void *) va_arg(inspect, intptr_t);
                sysctl_oldlenp = (size_t *) va_arg(inspect, intptr_t);

                shdw_proc_mib_kind_t kind = shdw_proc_mib_kind(sysctl_mib, sysctl_miblen);

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

                // Per-pid queries of a jailbreak daemon answer ENOENT (the same
                // hiding the KERN_PROC_ALL filter applies to the list). The own
                // pid passes — its record is sanitized after success below.
                if(kind == SHADW_PROC_MIB_PID_OTHER && shdw_pid_restricted_uncached(sysctl_mib[3])) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }

                // KERN_PROCARGS2 is a direct CTL_KERN child: {CTL_KERN, KERN_PROCARGS2, pid}.
                if(kind == SHADW_PROC_MIB_ARGS2_OTHER && shdw_pid_restricted_uncached(sysctl_mib[2])) {
                    errno = ENOENT;
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

            case SHADW_RAW_CAT_FDXATTR: {
                int fd = (int) va_arg(inspect, intptr_t);
                char pathname[PATH_MAX];

                // Same fd policy as the libc.x fgetxattr/flistxattr hooks:
                // resolve via F_GETPATH, fail open when the path can't be
                // named (the descriptor is legitimate — tty/pipe/socket).
                if(fcntl(fd, F_GETPATH, pathname) != -1 && [_shadow isCPathRestricted:pathname]) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
            } break;

            case SHADW_RAW_CAT_PATH: {
                const char* pathname = va_arg(inspect, const char *);

                if([_shadow isCPathRestricted:pathname]) {
                    errno = ENOENT;
                    va_end(inspect);
                    return -1;
                }
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
                if(result == 0 && csops_pid == getpid() && shdw_csops_apply_after_success(csops_ops, csops_useraddr, csops_usersize)) {
                    return -1;
                }
                break;

            case SHADW_RAW_CAT_SYSCTL:
                if(result == 0 && sysctl_mib) {
                    shdw_proc_mib_kind_t kind = shdw_proc_mib_kind(sysctl_mib, sysctl_miblen);

                    if(kind == SHADW_PROC_MIB_PID_SELF && sysctl_oldp && sysctl_oldlenp && *sysctl_oldlenp >= sizeof(struct kinfo_proc)) {
                        // Remove trace flags from our own process record.
                        // NOTE: the raw per-pid path deliberately does NOT rewrite
                        // e_ppid (the libc per-pid hook and the list filter do) —
                        // preserved as-is.
                        shdw_proc_sanitize_self_trace_flags((struct kinfo_proc *) sysctl_oldp);
                    }

                    // Own KERN_PROCARGS2: rebuild the raw payload to agree with the
                    // filtered NSProcessInfo/getenv views.
                    if(kind == SHADW_PROC_MIB_ARGS2_SELF && sysctl_oldp && sysctl_oldlenp && *sysctl_oldlenp > (size_t) sizeof(int)) {
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

            case SHADW_RAW_CAT_NONE:
            case SHADW_RAW_CAT_PATH:
            case SHADW_RAW_CAT_AT:
            case SHADW_RAW_CAT_FDXATTR:
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

    va_list args;
    va_start(args, number);
    long result = shdw_syscall_dispatch(number, args);
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

    va_list args;
    va_start(args, number);
    long result = shdw_syscall_dispatch(number, args);
    va_end(args);

    return result;
}

// CS_DEBUGGED (0x08000000) is an XNU-internal code-signing flag absent from
// Apple's public codesign.h (same situation as CS_JIT_ALLOW above): set while
// a process is under a debugger. Clearing it on kernels that expose it hides
// the debug state; on older kernels the bit is never set, so clearing is a
// no-op.
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x08000000
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
}

// Shared post-success csops policy, applied only after the original call
// SUCCEEDED (on a failed call the kernel wrote no status/hash, and a
// synthetic EBADEXEC on top of a real error would deviate from stock):
// CS_OPS_STATUS gets the clear-only sanitization at *useraddr (the flags are
// written into the CALLER's buffer, not returned — editing `ret` would
// corrupt the return value); CS_OPS_CDHASH is hidden. Returns YES when the
// call must be converted into a denial (errno set), NO to pass through.
static BOOL shdw_csops_apply_after_success(unsigned int ops, void* useraddr, size_t usersize) {
    if(ops == CS_OPS_STATUS && useraddr && usersize >= sizeof(uint32_t)) {
        shdw_csops_sanitize_status((uint32_t *) useraddr);
        return NO;
    }

    if(ops == CS_OPS_CDHASH) {
        // Hide CDHASH for trustcache checks.
        errno = EBADEXEC;
        return YES;
    }

    return NO;
}

static int (*original_csops)(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
static int replaced_csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
    BOOL ext = isCallerExternal();

    if(ext) {
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

    if(ext && pid == getpid() && ret == 0 && shdw_csops_apply_after_success(ops, useraddr, usersize)) {
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

    if(ext && ops == CS_OPS_MARKKILL && pid != getpid()) {
        errno = EBADEXEC;
        return -1;
    }

    int ret = original_csops_audittoken(pid, ops, useraddr, usersize, token);

    if(ext && ret == 0 && pid == getpid() && shdw_csops_apply_after_success(ops, useraddr, usersize)) {
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
        if(strcmp(name, "kern.proc.all") == 0) {
            // The original calls below re-enter the (possibly
            // __syscall-delegating) dispatch, hence reentrant = YES.
            return shdw_proc_all_filtered(shdw_raw_sysctl_original, oldp, oldlenp, YES);
        }

        static const char procPidPrefix[] = "kern.proc.pid.";

        if(strncmp(name, procPidPrefix, sizeof(procPidPrefix) - 1) == 0) {
            pid_t pid = (pid_t) atoi(name + sizeof(procPidPrefix) - 1);

            if(pid != getpid()) {
                // Per-pid query of a jailbreak daemon: same ENOENT hiding
                // the list filters apply.
                if(shdw_pid_restricted_uncached(pid)) {
                    errno = ENOENT;
                    return -1;
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
// NOTE: direct reads of the raw `environ` symbol are not covered (the
// snapshot is our own storage by contract; remedying the symbol itself
// needs a libSystem data-symbol rebind — not attempted).

extern char*** _NSGetEnviron(void);

static char*** (*original_NSGetEnviron)(void);
static char*** replaced_NSGetEnviron(void) {
    if(!isCallerExternal()) {
        return original_NSGetEnviron();
    }

    char*** snapshot = shdw_env_filtered_snapshot(environ);

    return snapshot ? snapshot : original_NSGetEnviron();
}

// todo: research on "supervised syscalls"
//
// syscall/__syscall/csops are hooked on a REBIND-ONLY lane, not `hooks`
// (auto-cover [INLINE, REBIND]). These libsystem_kernel exports are reached
// by most callers through a direct/pre-resolved branch inside the dyld
// shared cache rather than a rebindable GOT/import slot, so litehook's rebind
// backend finds zero matched slots and auto-cover falls back to
// HKStrategyInline: litehook_hook_memory patches the LIVE target's own
// prologue (unprotect -> memcpy 20 non-atomic bytes -> reprotect), with no
// synchronization against other threads. syscall()/csops() are among the
// hottest, most concurrently-called functions in any process; another thread
// reliably calls one of them during that exact write window and faults
// EXC_BAD_ACCESS/SIGBUS KERN_PROTECTION_FAILURE on the still-non-executable
// page. Reproduced deterministically on-device (co.communico.brampton,
// 3/3 launches, same signature) — this is a HookKit-level inline-patch race,
// not specific to these replacement functions; flagged upstream.
// A rebind-only substitutor never attempts the inline fallback: a
// zero-match target just fails HK_ERR_NOT_SUPPORTED, which these three calls
// already treat as "skip cleanly" (return value unchecked, matching the
// runtime-resolved siblings below). Coverage loss (raw syscall dispatch
// filtering / csops self-mark protection go unhooked on devices where these
// symbols aren't GOT-rebindable) is preferable to crashing the target app.
// Revert to `hooks` once HookKit's inline-patch path is made safe against
// concurrent execution of the target (thread suspension during the write, or
// an atomically-visible single-instruction redirect into an out-of-line stub).
void shadowhook_syscall(HKSubstitutor* hooks) {
    HKSubstitutor* rebindOnly = [HKSubstitutor substitutorWithCategory:HK_CAT_FUNCTION_REBIND];

    [rebindOnly hookFunction:syscall withReplacement:replaced_syscall outOldPtr:(void **) &original_syscall];
    [rebindOnly hookFunction:csops withReplacement:replaced_csops outOldPtr:(void **) &original_csops];

    // Runtime-resolve __syscall; skipped cleanly when absent.
    void* sym___syscall = shdw_resolve_libsystem("___syscall");
    // Some iOS builds export syscall and __syscall as the same entry point.
    // Address-based rebinders already cover every slot for that address; a
    // second replacement cannot coexist and only reports a false failure.
    if(sym___syscall && sym___syscall != (void *)syscall) {
        [rebindOnly hookFunction:sym___syscall withReplacement:replaced___syscall outOldPtr:(void **) &original___syscall];
    }

    // Misc sibling surfaces: runtime-resolved, skipped cleanly when absent.
    // Also on rebindOnly (bisection isolation, see the note above): these are
    // fewer/colder than syscall/csops but still direct-branch libsystem_kernel
    // exports, so leaving them on the inline-capable lane is the same hazard.
    void* sym_misc = shdw_resolve_libsystem("_sysctlbyname");
    if(sym_misc) {
        [rebindOnly hookFunction:sym_misc withReplacement:replaced_sysctlbyname outOldPtr:(void **) &original_sysctlbyname];
    }

    sym_misc = shdw_resolve_libsystem("___sysctlbyname");
    if(sym_misc) {
        [rebindOnly hookFunction:sym_misc withReplacement:replaced___sysctlbyname outOldPtr:(void **) &original___sysctlbyname];
    }

    sym_misc = shdw_resolve_libsystem("_csops_audittoken");
    if(sym_misc) {
        [rebindOnly hookFunction:sym_misc withReplacement:replaced_csops_audittoken outOldPtr:(void **) &original_csops_audittoken];
    }

    sym_misc = shdw_resolve_libsystem("_NSGetEnviron");
    if(sym_misc) {
        [rebindOnly hookFunction:sym_misc withReplacement:replaced_NSGetEnviron outOldPtr:(void **) &original_NSGetEnviron];
    }

    // Raw svc #0x80 interception (svc_patch.x): every image/region write is
    // serialized and stop-the-world, so the add-image, periodic, and
    // mprotect-triggered paths share the same live-code safety guarantee.
    shdw_svc_patch_install();
}

void shadowhook_syscall_verify(void) {
    // ___syscall/_sysctlbyname/___sysctlbyname/_csops_audittoken/_NSGetEnviron
    // are runtime-resolved: excluded (NULL is expected when absent).
    shdw_hook_check_t checks[] = {
        { "syscall", original_syscall },
        { "csops", original_csops },
    };

    shdw_verify_hooks("syscall", checks, sizeof(checks) / sizeof(checks[0]));
}
