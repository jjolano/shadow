#import "hooks.h"

void* (SecTaskCopyValueForEntitlement)(void* task, CFStringRef entitlement, CFErrorRef  _Nullable *error);
void* (SecTaskCreateFromSelf)(CFAllocatorRef allocator);

static kern_return_t (*original_task_for_pid)(task_port_t task, pid_t pid, task_port_t* target);
static kern_return_t replaced_task_for_pid(task_port_t task, pid_t pid, task_port_t* target) {
    return KERN_FAILURE;
    // // Check if the app has this entitlement (likely not).
    // CFErrorRef err = nil;
    // NSArray* ent = (__bridge NSArray *)SecTaskCopyValueForEntitlement(SecTaskCreateFromSelf(NULL), CFSTR("get-task-allow"), &err);

    // if(!ent || true) {
    //     NSLog(@"%@: %@", @"deny task_for_pid", @(pid));
    //     return KERN_FAILURE;
    // }

    // return %orig;
}

static kern_return_t (*original_host_get_special_port)(host_priv_t host_priv, int node, int which, mach_port_t* port);
static kern_return_t replaced_host_get_special_port(host_priv_t host_priv, int node, int which, mach_port_t* port) {
    // interesting ports: 4, HOST_SEATBELT_PORT, HOST_PRIV_PORT
    NSLog(@"%@: %d", @"host_get_special_port", which);

    if(node == HOST_LOCAL_NODE && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
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

    return original_host_get_special_port(host_priv, node, which, port);
}

static int (*original_csops)(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
static int replaced_csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
    int ret = original_csops(pid, ops, useraddr, usersize);

    if(pid == getpid() && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
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

static int (*original_sandbox_check)(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
static int replaced_sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...) {
    void* data[5];
    va_list args;
    va_start(args, type);
    data[0] = va_arg(args, void*);
    data[1] = va_arg(args, void*);
    data[2] = va_arg(args, void*);
    data[3] = va_arg(args, void*);
    data[4] = va_arg(args, void*);
    va_end(args);

    if(operation && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        NSString* op = @(operation);

        if(data[0]) {
            NSLog(@"%@: %@: %s", @"sandbox_check", op, (const char *)data[0]);
        } else {
            NSLog(@"%@: %@", @"sandbox_check", op);
        }

        if([op isEqualToString:@"mach-lookup"]) {
            if(data[0]) {
                NSString* name = @((const char *)data[0]);

                if(![name hasPrefix:@"com.apple"]) {
                    if([name hasPrefix:@"org.coolstar"]
                    || [name hasPrefix:@"com.ex"]
                    || [name hasPrefix:@"org.saurik"]
                    || [name hasPrefix:@"me.jjolano"]
                    || [name hasPrefix:@"lh:"]
                    || [name hasPrefix:@"cy:"]
                    || [name hasPrefix:@"rbs:"]) {
                        return -1;
                    }
                }
            }
        }

        if([op hasPrefix:@"file"]
        || [op isEqualToString:@"process-exec"]) {
            if(data[0]) {
                NSString* path = @((const char *)data[0]);

                if([path hasPrefix:@"/Library"] || [_shadow isPathRestricted:path]) {
                    return -1;
                }
            }
        }
    }

    return original_sandbox_check(pid, operation, type, data[0], data[1], data[2], data[3], data[4]);
}

static int (*original_fcntl)(int fd, int cmd, ...);
static int replaced_fcntl(int fd, int cmd, ...) {
    void* arg[6];
    va_list args;
    va_start(args, cmd);
    arg[0] = va_arg(args, void*);
    arg[1] = va_arg(args, void*);
    arg[2] = va_arg(args, void*);
    arg[3] = va_arg(args, void*);
    arg[4] = va_arg(args, void*);
    arg[5] = va_arg(args, void*);
    va_end(args);

    if(cmd == F_ADDSIGS) {
        // Prevent adding invalid code signatures.
        errno = EINVAL;
        return -1;
    }

    // if(cmd == F_CHECK_LV) {
    //     // Library Validation
    //     return 0;
    // }

    if(cmd == F_ADDFILESIGS_RETURN) {
        return -1;
    }

    return original_fcntl(fd, cmd, arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
}

void shadowhook_sandbox(void) {
    // %init(shadowhook_sandbox);

    MSHookFunction(sandbox_check, replaced_sandbox_check, (void **) &original_sandbox_check);
    MSHookFunction(fcntl, replaced_fcntl, (void **) &original_fcntl);
    MSHookFunction(csops, replaced_csops, (void **) &original_csops);
    MSHookFunction(host_get_special_port, replaced_host_get_special_port, (void **) &original_host_get_special_port);
    MSHookFunction(task_for_pid, replaced_task_for_pid, (void **) &original_task_for_pid);
}
