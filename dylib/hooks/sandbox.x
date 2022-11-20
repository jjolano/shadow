#import "hooks.h"

void* (SecTaskCopyValueForEntitlement)(void* task, CFStringRef entitlement, CFErrorRef  _Nullable *error);
void* (SecTaskCreateFromSelf)(CFAllocatorRef allocator);

%group shadowhook_sandbox
%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int ret = %orig;

    if(pid == getpid()) {
        if(ops == CS_OPS_STATUS) {
            // (Un)set some flags
            ret &= ~CS_PLATFORM_BINARY;
            ret &= ~CS_GET_TASK_ALLOW;
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

%hookf(kern_return_t, task_for_pid, task_port_t task, pid_t pid, task_port_t *target) {
    // Check if the app has this entitlement (likely not).
    CFErrorRef err = nil;
    NSArray* ent = (__bridge NSArray *)SecTaskCopyValueForEntitlement(SecTaskCreateFromSelf(NULL), CFSTR("get-task-allow"), &err);

    if(!ent || true) {
        HBLogDebug(@"%@: %@", @"deny task_for_pid", @(pid));
        return KERN_FAILURE;
    }

    return %orig;
}

%hookf(int, raise, int sig) {
    HBLogDebug(@"%@: %d", @"raise", sig);
    return %orig;
}

%hookf(int, kill, pid_t pid, int sig) {
    HBLogDebug(@"%@: %d", @"kill", sig);
    return %orig;
}

%hookf(sig_t, signal, int sig, sig_t func) {
    HBLogDebug(@"%@: %d", @"signal", sig);
    return %orig;
}

%hookf(int, sigaction, int sig, const struct sigaction *restrict act, struct sigaction *restrict oact) {
    HBLogDebug(@"%@: %d", @"sigaction", sig);
    return %orig;
}

%hookf(kern_return_t, host_get_special_port, host_priv_t host_priv, int node, int which, mach_port_t *port) {
    // interesting ports: 4, HOST_SEATBELT_PORT, HOST_PRIV_PORT
    HBLogDebug(@"%@: %d", @"host_get_special_port", which);

    if(node == HOST_LOCAL_NODE) {
        if(which == HOST_PRIV_PORT) {
            if(port) {
                *port = MACH_PORT_NULL;
            }

            return KERN_SUCCESS;
        }

        if(which == 4 /* kernel (hgsp4) */) {
            return KERN_FAILURE;
        }

        if(which == HOST_SEATBELT_PORT) {
            return KERN_FAILURE;
        }
    }

    return %orig;
}
%end

static int (*original_sandbox_check)(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
static int replaced_sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...) {
    void* data;
    va_list args;
    va_start(args, type);
    data = va_arg(args, void*);
    va_end(args);

    if(operation) {
        NSString* op = @(operation);

        if(op && data) {
            HBLogDebug(@"%@: %@: %s", @"sandbox_check", op, (const char *)data);
        } else {
            HBLogDebug(@"%@: %@", @"sandbox_check", op);
        }
    }

    return original_sandbox_check(pid, operation, type, data);
}

static int (*original_fcntl)(int fd, int cmd, ...);
static int replaced_fcntl(int fd, int cmd, ...) {
    void* arg;
    va_list args;
    va_start(args, cmd);
    arg = va_arg(args, void*);
    va_end(args);

    if(cmd == F_ADDSIGS) {
        // Prevent adding invalid code signatures.
        errno = EINVAL;
        return -1;
    }

    return arg ? original_fcntl(fd, cmd, arg) : original_fcntl(fd, cmd);
}

void shadowhook_sandbox(void) {
    %init(shadowhook_sandbox);

    MSHookFunction(sandbox_check, replaced_sandbox_check, (void **) &original_sandbox_check);
    MSHookFunction(fcntl, replaced_fcntl, (void **) &original_fcntl);
}
