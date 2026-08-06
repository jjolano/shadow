#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"

// Forwards a syscall() call with exact arguments. There is no v-syscall, so
// a va_list can't be forwarded through a variadic `...`: the trampoline
// re-reads the argument list and re-passes it with explicit parameters.
// Intercepted numbers get their real signatures (all of them take pointers
// and/or ints — reading pointer-width slots preserves every value); other
// numbers forward the 8-register window and surplus slots are ignored by
// the callee.
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
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);

            return original_syscall(number, (const char *) a1, (int) a2, (uid_t) a3, (gid_t) a4);
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

        default: {
            // Not intercepted: forward the 8-register window (same coverage
            // as the old memcpy of the save area, but ABI-portable). The
            // callee reads only the args its number declares.
            intptr_t a1 = va_arg(args, intptr_t);
            intptr_t a2 = va_arg(args, intptr_t);
            intptr_t a3 = va_arg(args, intptr_t);
            intptr_t a4 = va_arg(args, intptr_t);
            intptr_t a5 = va_arg(args, intptr_t);
            intptr_t a6 = va_arg(args, intptr_t);
            intptr_t a7 = va_arg(args, intptr_t);
            intptr_t a8 = va_arg(args, intptr_t);

            return original_syscall(number, a1, a2, a3, a4, a5, a6, a7, a8);
        }
    }
}

static long replaced_syscall(int number, ...) {
    NSLog(@"%@: %d", @"syscall", number);

    va_list args;
    va_start(args, number);

    // Read the decision args from a COPY so the forward trampoline below
    // still sees the full, unadvanced argument list.
    va_list inspect;
    va_copy(inspect, args);

    // Handle single pathname syscalls
    if(!isCallerTweak()) {
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
        || number == SYS_access_extended
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

static int (*original_csops)(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
static int replaced_csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
    int ret = original_csops(pid, ops, useraddr, usersize);

    if(!isCallerTweak() && pid == getpid()) {
        if(ops == CS_OPS_STATUS) {
            // (Un)set some flags
            ret &= ~CS_PLATFORM_BINARY;
            ret &= ~CS_GET_TASK_ALLOW;
            ret &= ~CS_INSTALLER;
            ret &= ~CS_ENTITLEMENTS_VALIDATED;
            ret |= 0x0000300; /* CS_JIT_ALLOW */
            ret |= CS_REQUIRE_LV;
        }

        if(ops == CS_OPS_CDHASH) {
            // Hide CDHASH for trustcache checks
            errno = EBADEXEC;
            return -1;
        }

        if(ops == CS_OPS_MARKKILL) {
            errno = EBADEXEC;
            return -1;
        }
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
