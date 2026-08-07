#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"

// Apple's real sandbox.h defines SANDBOX_CHECK_NO_REPORT as (1 << 16), a
// high-bit flag OR'd over the filter type; the vendored header declares it
// as an extern const instead, so use the stable value directly. Masking it
// off recovers the actual filter type (mach-lookup is called as
// SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT).
#define SHADOW_SANDBOX_CHECK_NO_REPORT  (1 << 16)

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
    if(!isCallerExternal()) {
        NSLog(@"%@: %d", @"task_for_pid", pid);
        return KERN_FAILURE;
    }
    
    return original_task_for_pid(task, pid, target);
}

static kern_return_t (*original_host_get_special_port)(host_priv_t host_priv, int node, int which, mach_port_t* port);
static kern_return_t replaced_host_get_special_port(host_priv_t host_priv, int node, int which, mach_port_t* port) {
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
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

    if(!isCallerExternal()) {
        NSLog(@"%@: %d", @"sigaction", sig);
    
        if(oact && ([_shadow isAddrRestricted:(oact->__sigaction_u).__sa_handler] || [_shadow isAddrRestricted:(oact->__sigaction_u).__sa_sigaction])) {
            memset(oact, 0, sizeof(struct sigaction));
        }
    }

    return result;
}

static int (*original_sandbox_check)(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
static int replaced_sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...) {
    va_list args;
    va_start(args, type);

    // The `type` argument carries flags (e.g. SANDBOX_CHECK_NO_REPORT) OR'd
    // over the filter type; decode the low bits for the inspection and
    // forward the ORIGINAL value unchanged.
    int filter_type = (int) type & ~SHADOW_SANDBOX_CHECK_NO_REPORT;

    // Key the inspection on the OPERATION string; only read the first
    // vararg as a string when the filter type is one of the name-taking
    // types (mach service lookups use GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT;
    // PATH/name filters likewise pass a string, PID/index-style types pass
    // an int and are forwarded without inspection).
    if(operation && strcmp(operation, "mach-lookup") == 0
    && (filter_type == SANDBOX_FILTER_GLOBAL_NAME || filter_type == SANDBOX_FILTER_LOCAL_NAME)) {
        // Read from a COPY so the forward below still sees the full list.
        va_list inspect;
        va_copy(inspect, args);
        const char* name = va_arg(inspect, const char *);
        va_end(inspect);

        // The tweak's own mach-lookup of its daemon service is always
        // allowed: the app sandbox would otherwise deny the vnode client's
        // bootstrap_look_up (sandbox_check is called regardless of caller).
        if(isCallerExternal() && name && strcmp(name, MACH_SERVICE_NAME) == 0) {
            va_end(args);
            return 0;
        }

        if(!isCallerExternal() && name
        && (strstr(name, "cy:") == name
        || strstr(name, "lh:") == name
        || strstr(name, "rbs:") == name
        || strstr(name, "jailbreakd") == name
        || strstr(name, "org.coolstar") == name
        || strstr(name, "com.ex") == name
        || strstr(name, "org.saurik") == name)) {
            va_end(args);
            return -1;
        }
    }

    // Forward the exact varargs for the filter type: NONE takes none, the
    // path/name family takes one string. (Int-taking filters from newer
    // runtimes fall into default: the slot round-trip preserves the value
    // and no string inspection runs for them.)
    switch(filter_type) {
        case SANDBOX_FILTER_NONE:
            va_end(args);
            return original_sandbox_check(pid, operation, type);

        default: {
            const char* filter_name = va_arg(args, const char *);
            va_end(args);
            return original_sandbox_check(pid, operation, type, filter_name);
        }
    }
}

static int (*original_fcntl)(int fd, int cmd, ...);
static int replaced_fcntl(int fd, int cmd, ...) {
    // Only commands that take a third argument get one read: the getters
    // (F_GETFD/F_GETFL/F_GETOWN/F_GETPROTECTIONCLASS/F_GETLEASE/...) take
    // none and must not consume a vararg the caller never passed. Anything
    // not listed below takes an argument (including F_SETSIZE).
    intptr_t arg = 0;
    off_t size_arg = 0;
    BOOL has_arg = YES;
    BOOL is_size_arg = NO;

    switch(cmd) {
        case F_GETFD:
        case F_GETFL:
        case F_GETOWN:
        case F_FULLFSYNC:
        case F_FLUSH_DATA:
        case F_CHKCLEAN:
        case F_FREEZE_FS:
        case F_THAW_FS:
        case F_BARRIERFSYNC:
        case F_GETNOSIGPIPE:
        case F_GETPROTECTIONLEVEL:
        case F_GETPROTECTIONCLASS:
#ifdef F_GETLEASE
        case F_GETLEASE:    /* iOS 16.5+ */
#endif
            has_arg = NO;
            break;

        case F_SETSIZE:
            // F_SETSIZE takes a 64-bit off_t: on armv7 reading the slot as
            // intptr_t would truncate it, so it is read/forwarded as off_t.
            is_size_arg = YES;
            break;

        default:
            break;
    }

    if(has_arg) {
        // The third argument's type is command-dependent: a pointer for
        // F_GETPATH/F_CHECK_LV, an int for F_SETFL/F_SETFD/.... Read the
        // full pointer-width slot (ints are int-promoted into it on arm64)
        // and pass it through unchanged — narrowing to int would truncate
        // pointers.
        va_list args;
        va_start(args, cmd);

        if(is_size_arg) {
            size_arg = va_arg(args, off_t);
        } else {
            arg = va_arg(args, intptr_t);
        }

        va_end(args);
    }

    if(!isCallerExternal()) {
        if(cmd == F_ADDSIGS) {
            // Prevent adding invalid code signatures.
            errno = EINVAL;
            return -1;
        }

        if(cmd == F_CHECK_LV) {
            // Library Validation
            if(arg != 0) {
                int result = original_fcntl(fd, cmd, (void *) arg);

                // Only interpret the caller's buffer after a SUCCESSFUL
                // original call — a failed call leaves it untouched.
                if(result == 0) {
                    fchecklv_t* checkInfo = (fchecklv_t *) arg;

                    // lv_error_message is optional: the kernel can succeed
                    // without providing one, so only clear it when present.
                    if(checkInfo->lv_error_message != NULL) {
                        ((char *) checkInfo->lv_error_message)[0] = '\0';
                    }
                }

                return result;
            }
        }

        if(cmd == F_ADDFILESIGS_RETURN) {
            return -1;
        }
    }

    if(has_arg) {
        if(is_size_arg) {
            return original_fcntl(fd, cmd, size_arg);
        }

        return original_fcntl(fd, cmd, (void *) arg);
    }

    return original_fcntl(fd, cmd);
}

static int fn_enosys() {
    errno = ENOSYS;
    return -1;
}

static int fn_posix_spawn_enosys() {
    // posix_spawn(2) reports failure as a POSITIVE errno-number return
    // value and does not set errno — returning -1 would violate the
    // contract. ENOENT matches the tweak's hidden-path denial style.
    return ENOENT;
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
    MSHookFunction(posix_spawn, fn_posix_spawn_enosys, NULL);
    MSHookFunction(posix_spawnp, fn_posix_spawn_enosys, NULL);
    MSHookFunction(fork, fn_enosys, NULL);
    MSHookFunction(vfork, fn_enosys, NULL);

    // void* sym_system = MSFindSymbol(NULL, "_system");

    // if(sym_system) {
    //     MSHookFunction(sym_system, replaced_system, NULL);
    // }
}
