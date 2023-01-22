#import "hooks.h"

// extern void* SecTaskCopyValueForEntitlement(void* task, CFStringRef entitlement, CFErrorRef  _Nullable *error);
// extern void* SecTaskCreateFromSelf(CFAllocatorRef allocator);

// extern int MISValidateSignatureAndCopyInfo(NSString* file, NSDictionary* options, NSDictionary** info);
// extern NSString* kMISValidationOptionAllowAdHocSigning;
// extern NSString* kMISValidationOptionRespectUppTrustAndAuthorization;

// static int (*original_MISValidateSignatureAndCopyInfo)(NSString* file, NSDictionary* options, NSDictionary** info);
// static int replaced_MISValidateSignatureAndCopyInfo(NSString* file, NSDictionary* options, NSDictionary** info) {
//     int result =  original_MISValidateSignatureAndCopyInfo(file, options, info);

//     if(result == 0) {
//         // Don't allow checking trust cache for self
//         if([file hasPrefix:[[NSBundle mainBundle] bundlePath]]
//         && options[kMISValidationOptionAllowAdHocSigning]
//         && options[kMISValidationOptionRespectUppTrustAndAuthorization]) {
//             return -1;
//         }

//         if([_shadow isPathRestricted:file]) {
//             return -1;
//         }
//     }

//     return result;
// }

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

    return original_host_get_special_port(host_priv, node, which, port);
}

static kern_return_t (*original_task_get_special_port)(task_inspect_t task, int which_port, mach_port_t *special_port);
static kern_return_t replaced_task_get_special_port(task_inspect_t task, int which_port, mach_port_t *special_port) {
    NSLog(@"%@: %d", @"task_get_special_port", which_port);

    if(task == mach_task_self()) {
        if(which_port == TASK_SEATBELT_PORT) {
            return KERN_FAILURE;
        }
    } else {
        return KERN_FAILURE;
    }

    return original_task_get_special_port(task, which_port, special_port);
}

static kern_return_t (*original_task_get_exception_ports)(task_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t old_handlers, exception_behavior_array_t old_behaviors, exception_flavor_array_t old_flavors);
static kern_return_t replaced_task_get_exception_ports(task_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t old_handlers, exception_behavior_array_t old_behaviors, exception_flavor_array_t old_flavors) {
    return original_task_get_exception_ports(task, exception_mask, masks, masksCnt, old_handlers, old_behaviors, old_flavors);
}

static int (*original_sigaction)(int sig, const struct sigaction *restrict act, struct sigaction *restrict oact);
static int replaced_sigaction(int sig, const struct sigaction *restrict act, struct sigaction *restrict oact) {
    int result = original_sigaction(sig, act, oact);
    NSLog(@"%@: %d", @"sigaction", sig);
    
    if(oact && ([_shadow isAddrRestricted:(oact->__sigaction_u).__sa_handler] || [_shadow isAddrRestricted:(oact->__sigaction_u).__sa_sigaction])) {
        memset(oact, 0, sizeof(struct sigaction));
    }

    return result;
}

// static int (*original_sandbox_check)(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
// static int replaced_sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...) {
//     void* data;
//     va_list args;
//     va_start(args, type);
//     data = va_arg(args, void*);
//     va_end(args);

//     if(operation) {
//         NSString* op = @(operation);

//         if(data) {
//             NSLog(@"%@: %@: %s", @"sandbox_check", op, (const char *)data);
//         } else {
//             NSLog(@"%@: %@", @"sandbox_check", op);
//         }

//         if([op isEqualToString:@"mach-lookup"]) {
//             if(data) {
//                 NSString* name = @((const char *)data);

//                 if(![name hasPrefix:@"com.apple"]) {
//                     if([name hasPrefix:@"org.coolstar"]
//                     || [name hasPrefix:@"com.ex"]
//                     || [name hasPrefix:@"org.saurik"]
//                     || [name hasPrefix:@"me.jjolano"]
//                     || [name hasPrefix:@"lh:"]
//                     || [name hasPrefix:@"cy:"]
//                     || [name hasPrefix:@"rbs:"]) {
//                         return -1;
//                     }
//                 }
//             }
//         }

//         if([op hasPrefix:@"file"]
//         || [op isEqualToString:@"process-exec"]) {
//             if(data) {
//                 NSString* path = @((const char *)data);

//                 if([_shadow isPathRestricted:path]) {
//                     return -1;
//                 }
//             }
//         }
//     }

//     return original_sandbox_check(pid, operation, type, data);
// }

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

    if(cmd == F_CHECK_LV) {
        // Library Validation
        if(arg[0]) {
            original_fcntl(fd, cmd, arg[0]);

            fchecklv_t* checkInfo = (fchecklv_t*) arg[0];
            ((char *) checkInfo->lv_error_message)[0] = '\0';

            return 0;
        }
    }

    if(cmd == F_ADDFILESIGS_RETURN) {
        return -1;
    }

    return original_fcntl(fd, cmd, arg[0], arg[1], arg[2], arg[3], arg[4], arg[5]);
}

static int (*original_execve)(const char* pathname, char* const argv[], char* const envp[]);
static int replaced_execve(const char* pathname, char* const argv[], char* const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_execve(pathname, argv, envp);
}

// static int (*original_execvpe)(const char* pathname, char* const argv[], char* const envp[]);
// static int replaced_execvpe(const char* pathname, char* const argv[], char* const envp[]) {
//     if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
//         errno = ENOENT;
//         return -1;
//     }

//     return original_execvpe(pathname, argv, envp);
// }

static int (*original_execvp)(const char* pathname, char* const argv[]);
static int replaced_execvp(const char* pathname, char* const argv[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_execvp(pathname, argv);
}

static int (*original_execv)(const char* pathname, char* const argv[]);
static int replaced_execv(const char* pathname, char* const argv[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_execv(pathname, argv);
}

static int (*original_posix_spawn)(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]);
static int replaced_posix_spawn(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_posix_spawn(pid, pathname, file_actions, attrp, argv, envp);
}


static int (*original_posix_spawnp)(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]);
static int replaced_posix_spawnp(pid_t* pid, const char* pathname, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]) {
    if([_shadow isCPathRestricted:pathname] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        errno = ENOENT;
        return -1;
    }

    return original_posix_spawnp(pid, pathname, file_actions, attrp, argv, envp);
}

void shadowhook_sandbox(HKSubstitutor* hooks) {
    // %init(shadowhook_sandbox);

    // MSHookFunction(sandbox_check, replaced_sandbox_check, (void **) &original_sandbox_check);
    MSHookFunction(fcntl, replaced_fcntl, (void **) &original_fcntl);
    MSHookFunction(host_get_special_port, replaced_host_get_special_port, (void **) &original_host_get_special_port);
    MSHookFunction(task_get_special_port, replaced_task_get_special_port, (void **) &original_task_get_special_port);
    MSHookFunction(task_get_exception_ports, replaced_task_get_exception_ports, (void **) &original_task_get_exception_ports);
    MSHookFunction(task_for_pid, replaced_task_for_pid, (void **) &original_task_for_pid);
    MSHookFunction(sigaction, replaced_sigaction, (void **) &original_sigaction);
    // MSHookFunction(MISValidateSignatureAndCopyInfo, replaced_MISValidateSignatureAndCopyInfo, (void **) &original_MISValidateSignatureAndCopyInfo);

    MSHookFunction(execve, replaced_execve, (void **) &original_execve);
    MSHookFunction(execvp, replaced_execvp, (void **) &original_execvp);
    //MSHookFunction(execvpe, replaced_execvpe, (void **) &original_execvpe);
    MSHookFunction(execv, replaced_execv, (void **) &original_execv);
    MSHookFunction(posix_spawn, replaced_posix_spawn, (void **) &original_posix_spawn);
    MSHookFunction(posix_spawnp, replaced_posix_spawnp, (void **) &original_posix_spawnp);

    // void* sym_system = MSFindSymbol(NULL, "_system");

    // if(sym_system) {
    //     MSHookFunction(sym_system, replaced_system, NULL);
    // }
}
