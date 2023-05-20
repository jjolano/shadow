#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"

static int (*original_syscall)(int number, ...);
static int replaced_syscall(int number, ...) {
    NSLog(@"%@: %d", @"syscall", number);

	va_list args;
	va_start(args, number);

    void* stack[8];
    memcpy(stack, args, sizeof(stack));

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
            const char* pathname = va_arg(args, const char *);

            if([_shadow isCPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }
        }
    }

    // Handle ptrace (anti debug)
    if(number == SYS_ptrace) {
        int _request = va_arg(args, int);

        if(_request == PT_DENY_ATTACH) {
            return 0;
        }
    }

    va_end(args);

    return original_syscall(number, stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7]);
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
