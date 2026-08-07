#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"

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
    && number != SYS_pathconf) {
        return original_syscall(number);
    }

    NSLog(@"%@: %d", @"syscall", number);

    va_list args;
    va_start(args, number);

    // Read the decision args from a COPY so the forward trampoline below
    // still sees the full, unadvanced argument list.
    va_list inspect;
    va_copy(inspect, args);

    // Handle single pathname syscalls. NOTE: SYS_access_extended is NOT
    // inspected — its first argument is a binary entries buffer, not a C
    // string; it is still forwarded with its exact arity below.
    if(!isCallerExternal()) {
        if(number == SYS_open
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
                va_end(args);
                return -1;
            }
        }
    }

    // Handle ptrace (anti debug)
    if(number == SYS_ptrace) {
        int _request = va_arg(inspect, int);

        if(_request == PT_DENY_ATTACH) {
            va_end(inspect);
            va_end(args);
            return 0;
        }
    }

    va_end(inspect);

    long result = shdw_syscall_forward(number, args);
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

// todo: research on "supervised syscalls"
void shadowhook_syscall(HKSubstitutor* hooks) {
    MSHookFunction(syscall, replaced_syscall, (void **) &original_syscall);
    MSHookFunction(csops, replaced_csops, (void **) &original_csops);

    // d4001001
    // const uint8_t bytes_svc80[] = {
    //     0x01, 0x10, 0x00, 0xd4
    // };

    // const uint8_t bytes_ret[] = {
    //     0xc0, 0x03, 0x5f, 0xd6
    // };
}
