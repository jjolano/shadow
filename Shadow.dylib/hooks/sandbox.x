#pragma clang diagnostic ignored "-Wdeprecated-declarations"

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
    if(!isCallerTweak()) {
        NSLog(@"%@: %d", @"task_for_pid", pid);
        return KERN_FAILURE;
    }
    
    return original_task_for_pid(task, pid, target);
}

static kern_return_t (*original_host_get_special_port)(host_priv_t host_priv, int node, int which, mach_port_t* port);
static kern_return_t replaced_host_get_special_port(host_priv_t host_priv, int node, int which, mach_port_t* port) {
    if(!isCallerTweak()) {
        NSLog(@"%@: %d", @"host_get_special_port", which);

        if(port) {
            *port = MACH_PORT_NULL;
        }

        return KERN_FAILURE;
    }

    return original_host_get_special_port(host_priv, node, which, port);
}

static kern_return_t (*original_task_get_special_port)(task_inspect_t task, int which_port, mach_port_t *special_port);
static kern_return_t replaced_task_get_special_port(task_inspect_t task, int which_port, mach_port_t *special_port) {
    if(!isCallerTweak()) {
        NSLog(@"%@: %d", @"task_get_special_port", which_port);

        if(special_port) {
            *special_port = MACH_PORT_NULL;
        }
        
        return KERN_FAILURE;
    }

    return original_task_get_special_port(task, which_port, special_port);
}

// static kern_return_t (*original_task_get_exception_ports)(task_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t old_handlers, exception_behavior_array_t old_behaviors, exception_flavor_array_t old_flavors);
// static kern_return_t replaced_task_get_exception_ports(task_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t old_handlers, exception_behavior_array_t old_behaviors, exception_flavor_array_t old_flavors) {
//     return original_task_get_exception_ports(task, exception_mask, masks, masksCnt, old_handlers, old_behaviors, old_flavors);
// }

static int (*original_sigaction)(int sig, const struct sigaction *restrict act, struct sigaction *restrict oact);
static int replaced_sigaction(int sig, const struct sigaction *restrict act, struct sigaction *restrict oact) {
    int result = original_sigaction(sig, act, oact);

    if(!isCallerTweak()) {
        NSLog(@"%@: %d", @"sigaction", sig);
    
        if(oact && ([_shadow isAddrRestricted:(oact->__sigaction_u).__sa_handler] || [_shadow isAddrRestricted:(oact->__sigaction_u).__sa_sigaction])) {
            memset(oact, 0, sizeof(struct sigaction));
        }
    }

    return result;
}

static int (*original_sandbox_check)(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
static int replaced_sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...) {
    void* data[5];
    va_list args;
    va_start(args, type);

    for(int i = 0; i < 5; i++) {
        data[i] = va_arg(args, void *);
    }

    va_end(args);

    if(!isCallerTweak() && operation && strcmp(operation, "mach-lookup") == 0 && data[0]) {
        const char* name = (const char *)data[0];

        if(strstr(name, "cy:") == name
        || strstr(name, "lh:") == name
        || strstr(name, "rbs:") == name
        || strstr(name, "jailbreakd") == name
        || strstr(name, "org.coolstar") == name
        || strstr(name, "com.ex") == name
        || strstr(name, "org.saurik") == name) {
            return -1;
        }
    }

    return original_sandbox_check(pid, operation, type, data[0], data[1], data[2], data[3], data[4]);
}

static int (*original_fcntl)(int fd, int cmd, ...);
static int replaced_fcntl(int fd, int cmd, ...) {
    void* arg;
    va_list args;
    va_start(args, cmd);
    arg = va_arg(args, void *);
    va_end(args);

    if(!isCallerTweak()) {
        if(cmd == F_ADDSIGS) {
            // Prevent adding invalid code signatures.
            errno = EINVAL;
            return -1;
        }

        if(cmd == F_CHECK_LV) {
            // Library Validation
            if(arg) {
                original_fcntl(fd, cmd, arg);

                fchecklv_t* checkInfo = (fchecklv_t *) arg;
                ((char *) checkInfo->lv_error_message)[0] = '\0';

                return 0;
            }
        }

        if(cmd == F_ADDFILESIGS_RETURN) {
            return -1;
        }
    }

    return original_fcntl(fd, cmd, arg);
}

static int fn_enosys() {
    errno = ENOSYS;
    return -1;
}

// static int replaced_system(const char* command) {
//     if(command == NULL) return 0;
//     errno = ENOSYS;
//     return -1;
// }

void shadowhook_sandbox(HKSubstitutor* hooks) {
    // %init(shadowhook_sandbox);

    MSHookFunction(sandbox_check, replaced_sandbox_check, (void **) &original_sandbox_check);
    MSHookFunction(fcntl, replaced_fcntl, (void **) &original_fcntl);
    MSHookFunction(host_get_special_port, replaced_host_get_special_port, (void **) &original_host_get_special_port);
    MSHookFunction(task_get_special_port, replaced_task_get_special_port, (void **) &original_task_get_special_port);
    // MSHookFunction(task_get_exception_ports, replaced_task_get_exception_ports, (void **) &original_task_get_exception_ports);
    MSHookFunction(task_for_pid, replaced_task_for_pid, (void **) &original_task_for_pid);
    MSHookFunction(sigaction, replaced_sigaction, (void **) &original_sigaction);
    // MSHookFunction(MISValidateSignatureAndCopyInfo, replaced_MISValidateSignatureAndCopyInfo, (void **) &original_MISValidateSignatureAndCopyInfo);

    MSHookFunction(execle, fn_enosys, NULL);
    MSHookFunction(execlp, fn_enosys, NULL);
    MSHookFunction(execl, fn_enosys, NULL);
    MSHookFunction(execve, fn_enosys, NULL);
    MSHookFunction(execvp, fn_enosys, NULL);
    MSHookFunction(execv, fn_enosys, NULL);
    MSHookFunction(posix_spawn, fn_enosys, NULL);
    MSHookFunction(posix_spawnp, fn_enosys, NULL);
    MSHookFunction(fork, fn_enosys, NULL);
    MSHookFunction(vfork, fn_enosys, NULL);

    // void* sym_system = MSFindSymbol(NULL, "_system");

    // if(sym_system) {
    //     MSHookFunction(sym_system, replaced_system, NULL);
    // }
}
