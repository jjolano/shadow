#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"

#import <unistd.h>

// Shared bootstrap-service matcher defined in mach.x (see there); used by
// the mach-lookup denial below. Deliberately not in hooks.h — only the
// bootstrap hooks and this file consume it.
extern BOOL shdw_bootstrap_service_restricted(const char* name);

// The `type` argument of sandbox_check carries flag bits (SANDBOX_CHECK_NO_REPORT
// and friends) OR'd over the filter type. The flag values are not stable
// across OS versions — Apple's public header says (1 << 16), while the
// dyld3/WebKit fallback enums use 0x40000000 — and the vendored header
// declares them as extern consts with no compile-time value. The flags never
// collide with the filter-type range (0..17), so the low 5 bits recover the
// type for inspection. The ORIGINAL `type` is always forwarded unchanged.
#define SHADOW_SANDBOX_FILTER_TYPE_MASK 0x1F

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
    if(isCallerExternal()) {
        return original_task_for_pid(task, pid, target);
    }

    kern_return_t result = original_task_for_pid(task, pid, target);

    // Hide only the unexpected elevation: a SUCCESS for a process other than
    // self — stock iOS only grants task_for_pid to entitled processes, so a
    // non-self success is jailbreak-acquired. Deallocate the obtained right,
    // clear the output port, report the stock failure. Self task_for_pid is
    // a legitimate app pattern and passes through.
    if(result == KERN_SUCCESS && pid != getpid()) {
        if(target && *target != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *target);
            *target = MACH_PORT_NULL;
        }

        return KERN_FAILURE;
    }

    return result;
}

static kern_return_t (*original_host_get_special_port)(host_priv_t host_priv, int node, int which, mach_port_t* port);
static kern_return_t replaced_host_get_special_port(host_priv_t host_priv, int node, int which, mach_port_t* port) {
    if(isCallerExternal()) {
        return original_host_get_special_port(host_priv, node, which, port);
    }

    kern_return_t result = original_host_get_special_port(host_priv, node, which, port);

    // HOST_PRIV_PORT is the jailbreak elevation: stock iOS denies it to
    // unentitled processes, so a SUCCESS is the anomaly. Every other special
    // port (HOST_PORT, HOST_BOOTSTRAP_PORT, ...) is stock-expected and
    // passes through.
    if(result == KERN_SUCCESS && which == HOST_PRIV_PORT) {
        if(port && *port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *port);
            *port = MACH_PORT_NULL;
        }

        return KERN_FAILURE;
    }

    return result;
}

static kern_return_t (*original_task_get_special_port)(task_inspect_t task, int which_port, mach_port_t *special_port);
static kern_return_t replaced_task_get_special_port(task_inspect_t task, int which_port, mach_port_t *special_port) {
    if(isCallerExternal()) {
        return original_task_get_special_port(task, which_port, special_port);
    }

    kern_return_t result = original_task_get_special_port(task, which_port, special_port);

    // TASK_BOOTSTRAP_PORT (and TASK_ACCESS_PORT, which XPC reads on stock)
    // are stock-expected and pass through. A SUCCESS for any other special
    // port (TASK_KERNEL_PORT/TASK_DEBUG_PORT/...) is the jailbreak
    // elevation: deallocate the right, clear the output, report the stock
    // failure.
    if(result == KERN_SUCCESS
    && which_port != TASK_BOOTSTRAP_PORT
    && which_port != TASK_ACCESS_PORT) {
        if(special_port && *special_port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), *special_port);
            *special_port = MACH_PORT_NULL;
        }

        return KERN_FAILURE;
    }

    return result;
}

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

// sandbox_check file-operation policy: a restricted path under a
// file-read/file-write operation is denied. Write operations classify with
// write intent (a probe target that does not exist yet must still be
// denied); reads with read intent. Relative paths resolve against the
// process cwd, same as the *at family. Returns YES when the query must be
// denied — the caller reports the normal positive denial (1).
static BOOL shdw_sandbox_check_file_denied(const char* operation, const char* path) {
    if(!operation || !path) {
        return NO;
    }

    BOOL is_write = strncmp(operation, "file-write-", 11) == 0;

    if(strcmp(operation, "file-read-data") != 0
    && strcmp(operation, "file-read-metadata") != 0
    && !is_write) {
        return NO;
    }

    NSString* pathString = [NSString stringWithUTF8String:path];

    NSMutableDictionary* options = [NSMutableDictionary dictionaryWithObject:(is_write ? kShadowRestrictionOpWrite : kShadowRestrictionOpRead)
                                                                      forKey:kShadowRestrictionOperation];

    if(path[0] != '/') {
        char cwd[PATH_MAX];

        if(!getcwd(cwd, sizeof(cwd))) {
            return NO;
        }

        options[kShadowRestrictionWorkingDir] = [NSString stringWithUTF8String:cwd];
    }

    return [_shadow isPathRestricted:pathString options:options];
}

// Shared name/path inspection for sandbox_check and
// sandbox_check_by_audit_token: reads the first vararg of `inspect` (a copy
// owned by the caller) as a string and returns YES when the query must be
// denied. Only the name/path-taking filter types are inspected; int-taking
// types are never read here.
static BOOL shdw_sandbox_check_inspect(const char* operation, int filter_type, va_list inspect) {
    if(!operation) {
        return NO;
    }

    if(filter_type == SANDBOX_FILTER_GLOBAL_NAME || filter_type == SANDBOX_FILTER_LOCAL_NAME) {
        const char* name = va_arg(inspect, const char *);

        return strcmp(operation, "mach-lookup") == 0 && name && shdw_bootstrap_service_restricted(name);
    }

    if(filter_type == SANDBOX_FILTER_PATH) {
        const char* path = va_arg(inspect, const char *);

        return shdw_sandbox_check_file_denied(operation, path);
    }

    return NO;
}

static int (*original_sandbox_check)(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
static int replaced_sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...) {
    va_list args;
    va_start(args, type);

    // Key the inspection on the OPERATION string; only read the first
    // vararg as a string when the filter type is one of the name/path-taking
    // types (mach service lookups use GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT;
    // file checks use PATH; PID/index-style types pass an int and are
    // forwarded without inspection).
    if(!isCallerExternal() && operation) {
        // Read from a COPY so the forward below still sees the full list.
        va_list inspect;
        va_copy(inspect, args);

        if(shdw_sandbox_check_inspect(operation, (int) type & SHADOW_SANDBOX_FILTER_TYPE_MASK, inspect)) {
            va_end(inspect);
            va_end(args);

            // Positive denial: stock reports a profile-denied operation as
            // 1; -1 is reserved for operations unknown to the profile and
            // would fingerprint the hook.
            return 1;
        }

        va_end(inspect);
    }

    // The tweak's own mach-lookup of its daemon service is always allowed:
    // the app sandbox would otherwise deny the vnode client's
    // bootstrap_look_up (sandbox_check is called regardless of caller).
    if(isCallerExternal() && operation && strcmp(operation, "mach-lookup") == 0
    && (((int) type & SHADOW_SANDBOX_FILTER_TYPE_MASK) == SANDBOX_FILTER_GLOBAL_NAME
    || ((int) type & SHADOW_SANDBOX_FILTER_TYPE_MASK) == SANDBOX_FILTER_LOCAL_NAME)) {
        va_list inspect;
        va_copy(inspect, args);
        const char* name = va_arg(inspect, const char *);
        va_end(inspect);

        if(name && strcmp(name, MACH_SERVICE_NAME) == 0) {
            va_end(args);
            return 0;
        }
    }

    // Forward the exact varargs for the filter type: NONE takes none, the
    // path/name family takes one string. (Int-taking filters from newer
    // runtimes fall into default: the slot round-trip preserves the value
    // and no string inspection runs for them.)
    switch((int) type & SHADOW_SANDBOX_FILTER_TYPE_MASK) {
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
