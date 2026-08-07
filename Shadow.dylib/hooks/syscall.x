#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"

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
static long (*original_syscall)(int number, ...);

static long shdw_syscall_forward(int number, va_list args) {
    switch(number) {
        case SYS_chdir:
        case SYS_chroot:
        case SYS_rmdir:
            return original_syscall(number, (const char *) va_arg(args, intptr_t));

        case SYS_access:
        case SYS_stat:
        case SYS_lstat:
        case SYS_stat64:
        case SYS_lstat64:
        case SYS_pathconf: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);

            return original_syscall(number, (const char *) a1, (int) a2);
        }

        case SYS_execve: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);

            return original_syscall(number, (const char *) a1, (char *const *) a2, (char *const *) a3);
        }

        case SYS_readlink: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);

            return original_syscall(number, (const char *) a1, (char *) a2, (size_t) a3);
        }

        case SYS_open: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);

            // open only takes a mode when O_CREAT is set.
            if(((int) a2) & O_CREAT) {
                intptr_t a3 = va_arg(args, intptr_t);

                return original_syscall(number, (const char *) a1, (int) a2, (mode_t) a3);
            }

            return original_syscall(number, (const char *) a1, (int) a2);
        }

        case SYS_openat: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);

            // openat only takes a mode when O_CREAT is set.
            if(((int) a2) & O_CREAT) {
                intptr_t a3 = va_arg(args, intptr_t);

                return original_syscall(number, (int) a1, (const char *) a2, (mode_t) a3);
            }

            return original_syscall(number, (int) a1, (const char *) a2);
        }

        case SYS_fstatat:
        case SYS_fstatat64: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);

            return original_syscall(number, (int) a1, (const char *) a2, (struct stat *) a3, (int) a4);
        }

        case SYS_csops: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);

            return original_syscall(number, (pid_t) a1, (unsigned int) a2, (void *) a3, (size_t) a4);
        }

        case SYS_sysctl: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);
            intptr_t a5 = va_arg(args, intptr_t);
            intptr_t a6 = va_arg(args, intptr_t);

            return original_syscall(number, (int *) a1, (u_int) a2, (void *) a3, (size_t *) a4, (void *) a5, (size_t) a6);
        }

        case SYS_stat_extended:
        case SYS_lstat_extended:
        case SYS_stat64_extended:
        case SYS_lstat64_extended: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);

            return original_syscall(number, (const char *) a1, (void *) a2, (void *) a3, (size_t) a4);
        }

        case SYS_access_extended: {
            // Real signature: (entries, size_t, results, uid_t) — a binary
            // buffer, NOT a path string. Forward the slots untouched; the
            // inspection in replaced_syscall deliberately skips this number.
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);

            return original_syscall(number, (void *) a1, (size_t) a2, (void *) a3, (uid_t) a4);
        }

        case SYS_ptrace: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);

            return original_syscall(number, (int) a1, (pid_t) a2, (caddr_t) a3, (int) a4);
        }

        case SYS_getattrlist: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);
            intptr_t a5 = va_arg(args, intptr_t);

            return original_syscall(number, (const char *) a1, (void *) a2, (void *) a3, (size_t) a4, (unsigned long) a5);
        }

        case SYS_open_extended: {
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);
            intptr_t a5 = va_arg(args, intptr_t);
            intptr_t a6 = va_arg(args, intptr_t);

            return original_syscall(number, (const char *) a1, (int) a2, (uid_t) a3, (gid_t) a4, (int) a5, (void *) a6);
        }

        default:
            // Unreachable: replaced_syscall only forwards the intercepted
            // set (the OR-chain at its top). Keep this switch and that
            // chain in sync — a mismatch drops the args of a forwarded
            // syscall, so degrade to the register passthrough rather than
            // reading unknown arities.
            return original_syscall(number);
    }
}

// Minimal dirfd resolution for the raw *at syscalls — mirrors libc.x's
// shdw_resolve_dirfd_path (which is static to that file): absolute paths
// ignore dirfd; AT_FDCWD resolves against the cwd; other dirfds resolve via
// F_GETPATH. Returns YES when the query must be denied (errno = ENOENT
// set). Unresolvable-but-valid dir vnodes fail closed; invalid descriptors
// replay the original so the kernel reports the genuine error.
static BOOL shdw_raw_at_path_denied(int dirfd, const char* pathname) {
    if(pathname == NULL || pathname[0] == '\0') {
        return NO;
    }

    if(pathname[0] == '/') {
        return [_shadow isCPathRestricted:pathname];
    }

    char parent[PATH_MAX];

    if(dirfd == AT_FDCWD) {
        if(!getcwd(parent, sizeof(parent))) {
            errno = ENOENT;
            return YES;
        }
    } else if(fcntl(dirfd, F_GETPATH, parent) == -1) {
        struct stat st;

        if(fstat(dirfd, &st) == 0 && S_ISDIR(st.st_mode)) {
            // Valid directory vnode that can't be named: fail closed.
            errno = ENOENT;
            return YES;
        }

        // Invalid or non-directory descriptor: the kernel reports the
        // genuine error (EBADF/ENOTDIR) — never synthesize one here.
        return NO;
    }

    return [_shadow isPathRestricted:[NSString stringWithUTF8String:pathname]
        options:@{kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:parent]}];
}

// proc_pidpath is a stable libSystem export; declared here as in libc.x.
extern int proc_pidpath(int pid, void* buffer, uint32_t buffersize);

// Classifies a process as restricted (jailbreak daemon) by its executable
// path — mirrors libc.x's shdw_proc_is_restricted (static there). When
// proc_pidpath fails the process cannot be classified and is kept: denying
// legitimate processes would corrupt the process count on stock devices.
static BOOL shdw_raw_proc_is_restricted(pid_t pid) {
    char path[PATH_MAX];

    if(proc_pidpath(pid, path, sizeof(path)) > 0) {
        return [_shadow isCPathRestricted:path];
    }

    return NO;
}

// Filtered KERN_PROC_ALL enumeration for raw SYS_sysctl — mirrors libc.x's
// shdw_sysctl_proc_all (static there): two-phase size/full query with one
// churn retry, restricted processes removed, self trace flags cleared,
// size-only and short-buffer semantics preserved. Reentrancy-guarded: the
// original_syscall calls below re-enter the (possibly __syscall-delegating)
// dispatch, which must not re-apply this policy.
static _Thread_local BOOL shdw_raw_sysctl_proc_all_in_progress = NO;

static int shdw_raw_sysctl_proc_all(void* oldp, size_t* oldlenp) {
    int procMIB[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };

    shdw_raw_sysctl_proc_all_in_progress = YES;

    size_t capacity = 0;
    int ret = original_syscall(SYS_sysctl, procMIB, (u_int) 3, NULL, &capacity, NULL, (size_t) 0);

    if(ret != 0) {
        shdw_raw_sysctl_proc_all_in_progress = NO;
        return ret;  // kernel owns the error and *oldlenp
    }

    // Slack for process churn between the size and full queries.
    capacity += sizeof(struct kinfo_proc) * 8;

    struct kinfo_proc* procs = malloc(capacity);

    if(!procs) {
        errno = ENOMEM;
        shdw_raw_sysctl_proc_all_in_progress = NO;
        return -1;
    }

    size_t actual = capacity;
    ret = original_syscall(SYS_sysctl, procMIB, (u_int) 3, procs, &actual, NULL, (size_t) 0);

    if(ret != 0 && errno == ENOMEM) {
        // Churn outgrew the first buffer: retry once with the kernel's size.
        free(procs);
        capacity = actual;
        procs = malloc(capacity);

        if(!procs) {
            errno = ENOMEM;
            shdw_raw_sysctl_proc_all_in_progress = NO;
            return -1;
        }

        actual = capacity;
        ret = original_syscall(SYS_sysctl, procMIB, (u_int) 3, procs, &actual, NULL, (size_t) 0);
    }

    if(ret != 0) {
        free(procs);
        shdw_raw_sysctl_proc_all_in_progress = NO;
        return ret;
    }

    int count = (int)(actual / sizeof(struct kinfo_proc));
    int out = 0;

    for(int i = 0; i < count; i++) {
        struct kinfo_proc* p = &procs[i];

        if(p->kp_proc.p_pid == getpid()) {
            // Never report our own trace flags.
            p->kp_proc.p_flag &= ~P_TRACED;
            p->kp_proc.p_flag &= ~P_SELECT;
        } else if(shdw_raw_proc_is_restricted(p->kp_proc.p_pid)) {
            continue;  // jailbreak daemon: removed from the list
        }

        if(out != i) {
            procs[out] = procs[i];
        }

        out++;
    }

    size_t needed = (size_t) out * sizeof(struct kinfo_proc);

    if(oldp == NULL) {
        // Size-only query: report the filtered byte count.
        *oldlenp = needed;
        free(procs);
        shdw_raw_sysctl_proc_all_in_progress = NO;
        return 0;
    }

    if(*oldlenp < needed) {
        // Short buffer: stock sysctl semantics (ENOMEM + required size).
        *oldlenp = needed;
        free(procs);
        errno = ENOMEM;
        shdw_raw_sysctl_proc_all_in_progress = NO;
        return -1;
    }

    memcpy(oldp, procs, needed);
    *oldlenp = needed;
    free(procs);
    shdw_raw_sysctl_proc_all_in_progress = NO;
    return 0;
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

    // Handle single pathname syscalls. NOTE: SYS_access_extended is NOT
    // inspected — its first argument is a binary entries buffer, not a C
    // string; it is still forwarded with its exact arity below.
    if(!isCallerExternal()) {
        if(number == SYS_csops) {
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
        } else if(number == SYS_openat
        || number == SYS_fstatat
        || number == SYS_fstatat64) {
            int dirfd = (int) va_arg(inspect, intptr_t);
            const char* pathname = va_arg(inspect, const char *);

            // Same dirfd-aware path policy as the libc.x *at hooks.
            if(shdw_raw_at_path_denied(dirfd, pathname)) {
                va_end(inspect);
                return -1;  // errno set by the helper
            }
        } else if(number == SYS_sysctl) {
            sysctl_mib = (int *) va_arg(inspect, intptr_t);
            sysctl_miblen = (u_int) va_arg(inspect, intptr_t);
            sysctl_oldp = (void *) va_arg(inspect, intptr_t);
            sysctl_oldlenp = (size_t *) va_arg(inspect, intptr_t);

            // KERN_PROC_ALL process enumeration: same filtered-list policy
            // as the libc.x sysctl hook (static to that file).
            if(sysctl_mib && sysctl_miblen >= 3
            && sysctl_mib[0] == CTL_KERN
            && sysctl_mib[1] == KERN_PROC
            && sysctl_mib[2] == KERN_PROC_ALL
            && (sysctl_miblen == 3 || (sysctl_miblen == 4 && sysctl_mib[3] == 0))) {
                if(!shdw_raw_sysctl_proc_all_in_progress) {
                    int proc_ret = shdw_raw_sysctl_proc_all(sysctl_oldp, sysctl_oldlenp);
                    va_end(inspect);
                    return proc_ret;
                }
            }
        } else if(number == SYS_open
        || number == SYS_chdir
        || number == SYS_access
        || number == SYS_execve
        || number == SYS_chroot
        || number == SYS_rmdir
        || number == SYS_stat
        || number == SYS_lstat
        || number == SYS_getattrlist
        || number == SYS_open_extended
        || number == SYS_stat_extended
        || number == SYS_lstat_extended
        || number == SYS_stat64
        || number == SYS_lstat64
        || number == SYS_stat64_extended
        || number == SYS_lstat64_extended
        || number == SYS_readlink
        || number == SYS_pathconf) {
            const char* pathname = va_arg(inspect, const char *);

            if([_shadow isCPathRestricted:pathname]) {
                errno = ENOENT;
                va_end(inspect);
                return -1;
            }
        }
    }

    // Handle ptrace (anti debug)
    if(number == SYS_ptrace) {
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
    if(!isCallerExternal()) {
        if(number == SYS_csops && result == 0 && csops_pid == getpid() && shdw_csops_apply_after_success(csops_ops, csops_useraddr, csops_usersize)) {
            return -1;
        }

        if(number == SYS_sysctl && result == 0 && sysctl_mib && sysctl_miblen == 4
        && sysctl_mib[0] == CTL_KERN
        && sysctl_mib[1] == KERN_PROC
        && sysctl_mib[2] == KERN_PROC_PID
        && sysctl_mib[3] == getpid()
        && sysctl_oldp && sysctl_oldlenp && *sysctl_oldlenp >= sizeof(struct kinfo_proc)) {
            // Remove trace flags from our own process record.
            struct kinfo_proc* p = (struct kinfo_proc *) sysctl_oldp;

            if(p->kp_proc.p_flag & P_TRACED) {
                p->kp_proc.p_flag &= ~P_TRACED;
            }

            if(p->kp_proc.p_flag & P_SELECT) {
                p->kp_proc.p_flag &= ~P_SELECT;
            }
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
    // helper function or switch table).
    if(number != SYS_ptrace
    && number != SYS_open
    && number != SYS_chdir
    && number != SYS_access
    && number != SYS_execve
    && number != SYS_chroot
    && number != SYS_rmdir
    && number != SYS_stat
    && number != SYS_lstat
    && number != SYS_getattrlist
    && number != SYS_open_extended
    && number != SYS_stat_extended
    && number != SYS_lstat_extended
    && number != SYS_access_extended
    && number != SYS_stat64
    && number != SYS_lstat64
    && number != SYS_stat64_extended
    && number != SYS_lstat64_extended
    && number != SYS_readlink
    && number != SYS_pathconf
    && number != SYS_openat
    && number != SYS_fstatat
    && number != SYS_fstatat64
    && number != SYS_csops
    && number != SYS_sysctl) {
        return original_syscall(number);
    }

    NSLog(@"%@: %d", @"syscall", number);

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
    if(number != SYS_ptrace
    && number != SYS_open
    && number != SYS_chdir
    && number != SYS_access
    && number != SYS_execve
    && number != SYS_chroot
    && number != SYS_rmdir
    && number != SYS_stat
    && number != SYS_lstat
    && number != SYS_getattrlist
    && number != SYS_open_extended
    && number != SYS_stat_extended
    && number != SYS_lstat_extended
    && number != SYS_access_extended
    && number != SYS_stat64
    && number != SYS_lstat64
    && number != SYS_stat64_extended
    && number != SYS_lstat64_extended
    && number != SYS_readlink
    && number != SYS_pathconf
    && number != SYS_openat
    && number != SYS_fstatat
    && number != SYS_fstatat64
    && number != SYS_csops
    && number != SYS_sysctl) {
        return original___syscall(number);
    }

    NSLog(@"%@: %d", @"__syscall", number);

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
    if(!isCallerExternal()) {
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

    if(!isCallerExternal() && pid == getpid() && ret == 0 && shdw_csops_apply_after_success(ops, useraddr, usersize)) {
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
    if(!isCallerExternal() && ops == CS_OPS_MARKKILL && pid != getpid()) {
        errno = EBADEXEC;
        return -1;
    }

    int ret = original_csops_audittoken(pid, ops, useraddr, usersize, token);

    if(!isCallerExternal() && ret == 0 && pid == getpid() && shdw_csops_apply_after_success(ops, useraddr, usersize)) {
        return -1;
    }

    return ret;
}

// --- sysctlbyname/__sysctlbyname: kern.proc.* routed through the same
// filtering as the sysctl hook. The sysctl body lives in libc.x's
// antidebugging group and is static to that file, so the minimal KERN_PROC
// handling is re-implemented here (mirroring that group):
// "kern.proc.all" answers the filtered process list (via
// shdw_raw_sysctl_proc_all, same two-phase enumeration), and a
// KERN_PROC_PID query for self has its tracing flags cleared after a
// successful original call. ---

static int shdw_sysctlbyname_policy(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen, int (*original)(const char*, void*, size_t*, void*, size_t)) {
    if(!isCallerExternal() && name) {
        if(strcmp(name, "kern.proc.all") == 0) {
            return shdw_raw_sysctl_proc_all(oldp, oldlenp);
        }

        static const char procPidPrefix[] = "kern.proc.pid.";

        if(strncmp(name, procPidPrefix, sizeof(procPidPrefix) - 1) == 0
        && atoi(name + sizeof(procPidPrefix) - 1) == getpid()) {
            int ret = original(name, oldp, oldlenp, newp, newlen);

            // Remove trace flags from our own process record — only on
            // valid success and only when the buffer carries the record.
            if(ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                struct kinfo_proc* p = (struct kinfo_proc *) oldp;

                if(p->kp_proc.p_flag & P_TRACED) {
                    p->kp_proc.p_flag &= ~P_TRACED;
                }

                if(p->kp_proc.p_flag & P_SELECT) {
                    p->kp_proc.p_flag &= ~P_SELECT;
                }
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
// ponytail: the filter mirrors the libc.x envvar group's getenv policy
// (DYLD_INSERT_LIBRARIES + safe-mode flags); full DYLD_*/PATH sanitization
// lives in that group, and direct reads of the `environ` symbol are that
// lane's surface, not covered here. ---

extern char*** _NSGetEnviron(void);

static BOOL shdw_environ_var_hidden(const char* var) {
    static const char* hidden[] = {
        "DYLD_INSERT_LIBRARIES=",
        "_MSSafeMode=",
        "_SafeMode=",
        "_SubstituteSafeMode=",
        NULL
    };

    for(int i = 0; hidden[i]; i++) {
        if(strncmp(var, hidden[i], strlen(hidden[i])) == 0) {
            return YES;
        }
    }

    return NO;
}

static char*** (*original_NSGetEnviron)(void);
static char*** replaced_NSGetEnviron(void) {
    if(isCallerExternal()) {
        return original_NSGetEnviron();
    }

    size_t count = 0;

    while(environ[count]) {
        count++;
    }

    static char** filtered = NULL;
    static size_t filtered_capacity = 0;

    if(filtered_capacity < count + 1) {
        char** grown = realloc(filtered, (count + 1) * sizeof(char *));

        if(!grown) {
            return original_NSGetEnviron();
        }

        filtered = grown;
        filtered_capacity = count + 1;
    }

    size_t out = 0;

    for(size_t i = 0; i < count; i++) {
        if(shdw_environ_var_hidden(environ[i])) {
            continue;
        }

        filtered[out++] = environ[i];
    }

    filtered[out] = NULL;

    return &filtered;
}

// todo: research on "supervised syscalls"
void shadowhook_syscall(HKSubstitutor* hooks) {
    MSHookFunction(syscall, replaced_syscall, (void **) &original_syscall);
    MSHookFunction(csops, replaced_csops, (void **) &original_csops);

    // Runtime-resolve __syscall; skipped cleanly when absent.
    void* sym___syscall = MSFindSymbol(NULL, "___syscall");
    if(sym___syscall) {
        MSHookFunction(sym___syscall, replaced___syscall, (void **) &original___syscall);
    }

    // Misc sibling surfaces: runtime-resolved, skipped cleanly when absent.
    void* sym_misc = MSFindSymbol(NULL, "_sysctlbyname");
    if(sym_misc) {
        MSHookFunction(sym_misc, replaced_sysctlbyname, (void **) &original_sysctlbyname);
    }

    sym_misc = MSFindSymbol(NULL, "___sysctlbyname");
    if(sym_misc) {
        MSHookFunction(sym_misc, replaced___sysctlbyname, (void **) &original___sysctlbyname);
    }

    sym_misc = MSFindSymbol(NULL, "_csops_audittoken");
    if(sym_misc) {
        MSHookFunction(sym_misc, replaced_csops_audittoken, (void **) &original_csops_audittoken);
    }

    sym_misc = MSFindSymbol(NULL, "_NSGetEnviron");
    if(sym_misc) {
        MSHookFunction(sym_misc, replaced_NSGetEnviron, (void **) &original_NSGetEnviron);
    }

    // d4001001
    // const uint8_t bytes_svc80[] = {
    //     0x01, 0x10, 0x00, 0xd4
    // };

    // const uint8_t bytes_ret[] = {
    //     0xc0, 0x03, 0x5f, 0xd6
    // };
}
