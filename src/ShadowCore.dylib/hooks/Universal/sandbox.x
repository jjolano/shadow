#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "UniversalHooks.h"

#import <unistd.h>
#import <wordexp.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

// Present from the iOS 15 rootless floor.  Older SDKs did not expose the
// name, but forwarding command 102 is harmless there: only a successful
// path-returning call is filtered below.
#ifndef F_GETPATH_NOFIRMLINK
#define F_GETPATH_NOFIRMLINK 102
#endif

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

static kern_return_t (*original_task_for_pid)(task_port_t task, pid_t pid, task_port_t* target);
static kern_return_t replaced_task_for_pid(task_port_t task, pid_t pid, task_port_t* target) {
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
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
    if(!isCallerExternal()) {
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

    // Sanitize the previous-handler output only after the original
    // SUCCEEDED: a failed call leaves oact untouched, and zeroing it over a
    // real error would deviate from stock.
    if(isCallerExternal() && result == 0) {
        NSLog(@"%@: %d", @"sigaction", sig);

        if(oact && (shdw_addr_is_restricted((oact->__sigaction_u).__sa_handler) || shdw_addr_is_restricted((oact->__sigaction_u).__sa_sigaction))) {
            memset(oact, 0, sizeof(struct sigaction));
        }
    }

    return result;
}

// --- signal family: previous-handler output sanitized only after the
// original succeeds, mirroring replaced_sigaction. `filter` is the caller
// classification evaluated at the hook site (isCallerExternal() must never
// run inside a helper — its return-address read would classify the helper's
// caller instead of signal's caller). ---

typedef void (*shdw_sighandler_t)(int);

// Returns the previous handler to report: SIG_DFL when the real handler
// lives in a restricted image (a detector querying back a jailbreak-library
// handler sees "no handler"). SIG_ERR (failure) is never an address and
// passes through.
static shdw_sighandler_t shdw_signal_sanitize_previous(shdw_sighandler_t previous, BOOL filter) {
    if(filter && previous != SIG_ERR && shdw_addr_is_restricted((void *) previous)) {
        return SIG_DFL;
    }

    return previous;
}

static shdw_sighandler_t (*original_signal)(int sig, shdw_sighandler_t handler);
static shdw_sighandler_t replaced_signal(int sig, shdw_sighandler_t handler) {
    return shdw_signal_sanitize_previous(original_signal(sig, handler), isCallerExternal());
}

static shdw_sighandler_t (*original_bsd_signal)(int sig, shdw_sighandler_t handler);
static shdw_sighandler_t replaced_bsd_signal(int sig, shdw_sighandler_t handler) {
    return shdw_signal_sanitize_previous(original_bsd_signal(sig, handler), isCallerExternal());
}

static shdw_sighandler_t (*original___signal_nobind)(int sig, shdw_sighandler_t handler);
static shdw_sighandler_t replaced___signal_nobind(int sig, shdw_sighandler_t handler) {
    return shdw_signal_sanitize_previous(original___signal_nobind(sig, handler), isCallerExternal());
}

static int (*original___sigaction)(int sig, const struct sigaction* act, struct sigaction* oact);
static int replaced___sigaction(int sig, const struct sigaction* act, struct sigaction* oact) {
    int result = original___sigaction(sig, act, oact);

    if(isCallerExternal() && result == 0 && oact
    && (shdw_addr_is_restricted((oact->__sigaction_u).__sa_handler) || shdw_addr_is_restricted((oact->__sigaction_u).__sa_sigaction))) {
        memset(oact, 0, sizeof(struct sigaction));
    }

    return result;
}

// sandbox_check file-operation policy: a restricted path under a
// file-read/file-write operation is denied. Write operations classify with
// write intent (a probe target that does not exist yet must still be
// denied); reads with read intent. Relative paths resolve against the
// process cwd, same as the *at family. Returns YES when the query must be
// denied — the caller reports the normal positive denial (1).
// One immutable options dict per operation kind (read vs write), built once:
// no per-call NSMutableDictionary/NSString allocation. Relative paths get
// the working-dir key from the process cwd, fetched ONCE and cached with the
// dict; later relative queries reuse the existing cached cwd. The chdir/fchdir
// hooks call shdw_sandbox_invalidate_cwd after a successful directory change,
// so a relative query never resolves against a stale cwd.
static char shdw_sandbox_cached_cwd[PATH_MAX];
static NSDictionary* read_options = nil;
static NSDictionary* write_options = nil;

// Invalidates the cached process cwd (called by the chdir/fchdir hooks in
// libc.x after a successful directory change): the next relative-path query
// re-fetches getcwd and rebuilds the options dict.
void shdw_sandbox_invalidate_cwd(void) {
    shdw_sandbox_cached_cwd[0] = '\0';
    read_options = nil;
    write_options = nil;
}

static NSDictionary* shdw_sandbox_check_options(BOOL is_write, BOOL needs_cwd) {
    static dispatch_once_t read_once;
    static dispatch_once_t write_once;

    NSDictionary* options;

    if(is_write) {
        dispatch_once(&write_once, ^{
            write_options = @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
        });

        options = write_options;
    } else {
        dispatch_once(&read_once, ^{
            read_options = @{kShadowRestrictionOperation : kShadowRestrictionOpRead};
        });

        options = read_options;
    }

    if(needs_cwd && !options[kShadowRestrictionWorkingDir]) {
        if(!getcwd(shdw_sandbox_cached_cwd, sizeof(shdw_sandbox_cached_cwd))) {
            return nil;
        }

        options = @{kShadowRestrictionOperation : (is_write ? kShadowRestrictionOpWrite : kShadowRestrictionOpRead),
                    kShadowRestrictionWorkingDir : [NSString stringWithUTF8String:shdw_sandbox_cached_cwd]};

        if(is_write) {
            write_options = options;
        } else {
            read_options = options;
        }
    }

    return options;
}

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

    NSDictionary* options = shdw_sandbox_check_options(is_write, path[0] != '/');

    if(!options) {
        return NO;
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
    if(isCallerExternal() && operation) {
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

    if(isCallerExternal()) {
        if((cmd == F_GETPATH || cmd == F_GETPATH_NOFIRMLINK) && arg != 0) {
            int result = original_fcntl(fd, cmd, (void *) arg);

            // Do not disclose a hidden descriptor through either path
            // spelling. Internal F_GETPATH calls in PathPolicy bypass this
            // branch through isCallerExternal().
            if(result == 0 && [_shadow isCPathRestricted:(const char *) arg]) {
                errno = ENOENT;
                return -1;
            }

            return result;
        }

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

// --- exec family: typed wrappers (no more blanket ENOSYS anywhere) ---

extern char** environ;

static int (*original_execve)(const char* path, char* const argv[], char* const envp[]);
static int (*original_execvp)(const char* file, char* const argv[]);

// exec policy: a hidden executable path answers ENOENT (the tweak's hidden-
// path denial style); benign paths go to the original. Only app-origin
// callers are filtered. The classification must be passed in from the hook
// site: isCallerExternal() reads the return address, and inside this helper
// it would classify the hook's own frame (Shadow-owned) instead of the
// caller's.
static BOOL shdw_exec_path_denied(BOOL callerExternal, const char* path) {
    return callerExternal && path && [_shadow isCPathRestricted:path];
}

// Collects the NULL-terminated variadic argv of an execl* call into a
// malloc'd array (the varargs live in the caller's stack and are not
// contiguous). Returns NULL on allocation failure. The result converts
// implicitly to the char* const* the execve/execvp originals take.
static char** shdw_execl_collect_argv(va_list args) {
    int count = 0;

    va_list count_args;
    va_copy(count_args, args);

    while(va_arg(count_args, const char *) != NULL) {
        count++;
    }

    va_end(count_args);

    char** argv = calloc((size_t) count + 1, sizeof(char *));

    if(!argv) {
        return NULL;
    }

    for(int i = 0; i < count; i++) {
        argv[i] = (char *) va_arg(args, const char *);
    }

    argv[count] = NULL;

    return argv;
}

static int replaced_execl(const char* path, const char* arg0, ...) {
    if(shdw_exec_path_denied(isCallerExternal(), path)) {
        errno = ENOENT;
        return -1;
    }

    va_list args;
    va_start(args, arg0);
    char** argv = shdw_execl_collect_argv(args);
    va_end(args);

    if(!argv) {
        errno = ENOMEM;
        return -1;
    }

    // execl does not search PATH: dispatch through execve with the current
    // environment.
    int result = original_execve(path, argv, environ);
    free(argv);
    return result;
}

static int replaced_execlp(const char* file, const char* arg0, ...) {
    if(shdw_exec_path_denied(isCallerExternal(), file)) {
        errno = ENOENT;
        return -1;
    }

    va_list args;
    va_start(args, arg0);
    char** argv = shdw_execl_collect_argv(args);
    va_end(args);

    if(!argv) {
        errno = ENOMEM;
        return -1;
    }

    // execlp searches PATH: dispatch through execvp.
    int result = original_execvp(file, argv);
    free(argv);
    return result;
}

static int replaced_execle(const char* path, const char* arg0, ...) {
    if(shdw_exec_path_denied(isCallerExternal(), path)) {
        errno = ENOENT;
        return -1;
    }

    va_list args;
    va_start(args, arg0);
    char** argv = shdw_execl_collect_argv(args);
    // execle: the envp pointer follows the argv NULL terminator.
    char* const* envp = argv ? (char* const*) va_arg(args, const char *) : NULL;
    va_end(args);

    if(!argv) {
        errno = ENOMEM;
        return -1;
    }

    int result = original_execve(path, argv, envp);
    free(argv);
    return result;
}

static int replaced_execv(const char* path, char* const argv[]) {
    if(shdw_exec_path_denied(isCallerExternal(), path)) {
        errno = ENOENT;
        return -1;
    }

    return original_execve(path, argv, environ);
}

static int replaced_execvp(const char* file, char* const argv[]) {
    if(shdw_exec_path_denied(isCallerExternal(), file)) {
        errno = ENOENT;
        return -1;
    }

    return original_execvp(file, argv);
}

static int replaced_execve(const char* path, char* const argv[], char* const envp[]) {
    if(shdw_exec_path_denied(isCallerExternal(), path)) {
        errno = ENOENT;
        return -1;
    }

    return original_execve(path, argv, envp);
}

static int (*original_posix_spawn)(pid_t* pid, const char* path, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]);
static int replaced_posix_spawn(pid_t* pid, const char* path, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]) {
    if(isCallerExternal()) {
        if(pid) *pid = -1;
        // posix_spawn(2) reports failure as a POSITIVE errno-number return
        // value and does not set errno. Stock app sandboxes deny process
        // creation before execution; preserve ENOENT for hidden paths.
        return path && [_shadow isCPathRestricted:path] ? ENOENT : EPERM;
    }

    return original_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

static int (*original_posix_spawnp)(pid_t* pid, const char* file, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]);
static int replaced_posix_spawnp(pid_t* pid, const char* file, const posix_spawn_file_actions_t* file_actions, const posix_spawnattr_t* attrp, char* const argv[], char* const envp[]) {
    if(isCallerExternal()) {
        if(pid) *pid = -1;
        return file && [_shadow isCPathRestricted:file] ? ENOENT : EPERM;
    }

    return original_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
}

static pid_t (*original_fork)(void);
static pid_t (*resolved_fork)(void);
static pid_t replaced_fork(void) {
    if(isCallerExternal()) {
        // Stock-like denial for app-origin callers: the app sandbox refuses
        // fork with EPERM on stock iOS.
        errno = EPERM;
        return -1;
    }

    pid_t (*call_fork)(void) = original_fork ?: resolved_fork;

    if(!call_fork) {
        errno = ENOSYS;
        return -1;
    }

    return call_fork();
}

static pid_t (*original_vfork)(void);
static pid_t replaced_vfork(void) {
    if(isCallerExternal()) {
        errno = EPERM;
        return -1;
    }

    return original_vfork();
}

// --- system/popen/wordexp: the executed binary is /bin/sh, so the execve
// path check cannot fire on the command itself; any whitespace-separated
// token that looks like a path (starts with '~' or contains '/') and names a
// restricted path denies the whole command with the exec family's ENOENT
// style (wordexp uses WRDE_NOSPACE, below). A bare '~' resolves to the
// caller's own home — for app-origin callers never a restricted path — but
// the check stays uniform across the three surfaces. ponytail: no shell
// grammar parsing — quoted paths are not split; add a parser if a detector
// probes through quoting. ---

static BOOL shdw_command_hides_restricted_path(const char* command) {
    if(!command) {
        return NO;
    }

    size_t len = strlen(command);
    char* copy = malloc(len + 1);

    if(!copy) {
        return NO;
    }

    memcpy(copy, command, len + 1);

    BOOL denied = NO;
    char* save = NULL;

    for(char* token = strtok_r(copy, " \t\r\n", &save); token; token = strtok_r(NULL, " \t\r\n", &save)) {
        if((token[0] == '~' || strchr(token, '/')) && [_shadow isCPathRestricted:token]) {
            denied = YES;
            break;
        }
    }

    free(copy);
    return denied;
}

static int (*original_system)(const char* command);
static int replaced_system(const char* command) {
    if(command == NULL) {
        // Stock system(NULL) answers shell availability.
        return original_system(NULL);
    }

    if(isCallerExternal() && shdw_command_hides_restricted_path(command)) {
        errno = ENOENT;
        return -1;
    }

    return original_system(command);
}

static FILE* (*original_popen)(const char* command, const char* type);
static FILE* replaced_popen(const char* command, const char* type) {
    if(isCallerExternal() && shdw_command_hides_restricted_path(command)) {
        errno = ENOENT;
        return NULL;
    }

    return original_popen(command, type);
}

// wordexp: the words string is a command line ("ls /var/jb/usr/bin") whose
// expansion materializes concrete paths a detector then stats/reads — a
// restricted path embedded in the words must never expand. Same literal-token
// pre-scan as system/popen above (tokens are the pre-expansion words; no
// variable substitution is chased). A restricted token denies the whole
// expansion with WRDE_NOSPACE — a generic, stock-plausible failure; wordexp
// does not use errno, and callers treat the return code as an opaque error.
// The output struct is zeroed so an error-returning call leaves an empty
// expansion (we_wordc 0), never a partial one.
static int (*original_wordexp)(const char* words, wordexp_t* pwordexp, int flags);
static int replaced_wordexp(const char* words, wordexp_t* pwordexp, int flags) {
    if(isCallerExternal() && shdw_command_hides_restricted_path(words)) {
        memset(pwordexp, 0, sizeof(wordexp_t));
        return WRDE_NOSPACE;
    }

    return original_wordexp(words, pwordexp, flags);
}

// wordfree: pass-through, not hooked — it only frees a prior successful
// expansion, and after a denied wordexp the zeroed struct makes any wordfree
// a no-op (free(NULL)), so there is no surface to filter.

// sandbox_check_by_audit_token: applies the sandbox_check policy only when
// the token belongs to THIS process (a jailbreak library judging a foreign
// process is not our surface — pass through). The audit token's pid
// component is val[4] (AU_TOKEN_PID).
static int (*original_sandbox_check_by_audit_token)(audit_token_t token, const char *operation, enum sandbox_filter_type type, ...);
static int replaced_sandbox_check_by_audit_token(audit_token_t token, const char *operation, enum sandbox_filter_type type, ...) {
    va_list args;
    va_start(args, type);

    if(isCallerExternal() && (pid_t) token.val[4] == getpid() && operation) {
        // Read from a COPY so the forward below still sees the full list.
        va_list inspect;
        va_copy(inspect, args);

        if(shdw_sandbox_check_inspect(operation, (int) type & SHADOW_SANDBOX_FILTER_TYPE_MASK, inspect)) {
            va_end(inspect);
            va_end(args);
            return 1;
        }

        va_end(inspect);
    }

    // Forward with the exact varargs for the filter type (same arity matrix
    // as sandbox_check).
    switch((int) type & SHADOW_SANDBOX_FILTER_TYPE_MASK) {
        case SANDBOX_FILTER_NONE:
            va_end(args);
            return original_sandbox_check_by_audit_token(token, operation, type);

        default: {
            const char* filter_name = va_arg(args, const char *);
            va_end(args);
            return original_sandbox_check_by_audit_token(token, operation, type, filter_name);
        }
    }
}

// task_get_exception_ports: replay the pre-injection baseline for external
// self-task queries. Shadow's ctor pre-initializes ElleKit's exception-based
// hooking path (EKLaunchExceptionHandler), which registers a task-level
// handler right. Detectors (FreeRASP privilegedAccess, DeviceSecurityKit
// Debugger, RootHider Exception port) enumerate self-task exception ports and
// treat any handler the app did not install as injection evidence.
//
// shdw_exception_ports_snapshot() records the handler port-name set BEFORE
// ElleKit installs (called from the coordinator ctor). Any handler slot
// returned by the kernel whose port is not in that baseline is an injected
// right: drop it (deallocate the ref the kernel just handed us) and compact
// the reply so masksCnt/handlers/behaviors/flavors describe exactly the
// pre-injection configuration. Internal Shadow callers see the raw truth.
#define SHDW_EXC_SNAPSHOT_MAX 32
static mach_port_t shdw_exc_baseline_ports[SHDW_EXC_SNAPSHOT_MAX];
static mach_msg_type_number_t shdw_exc_baseline_count = 0;
static BOOL shdw_exc_baseline_valid = NO;

void shdw_exception_ports_snapshot(void) {
    if(shdw_exc_baseline_valid) return;
    exception_mask_t masks[SHDW_EXC_SNAPSHOT_MAX] = {0};
    exception_handler_t handlers[SHDW_EXC_SNAPSHOT_MAX] = {0};
    exception_behavior_t behaviors[SHDW_EXC_SNAPSHOT_MAX] = {0};
    thread_state_flavor_t flavors[SHDW_EXC_SNAPSHOT_MAX] = {0};
    mach_msg_type_number_t count = SHDW_EXC_SNAPSHOT_MAX;
    kern_return_t kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL,
        masks, &count, handlers, behaviors, flavors);
    if(kr != KERN_SUCCESS) {
        // No baseline could be read; treat as empty so injected handlers are
        // still filtered rather than leaking through.
        shdw_exc_baseline_count = 0;
        shdw_exc_baseline_valid = YES;
        return;
    }
    for(mach_msg_type_number_t i = 0; i < count && i < SHDW_EXC_SNAPSHOT_MAX; i++) {
        shdw_exc_baseline_ports[shdw_exc_baseline_count++] = handlers[i];
        // Release the send ref the query handed us; we only keep the name for
        // identity comparison, not an owning right.
        if(handlers[i] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), handlers[i]);
        }
    }
    shdw_exc_baseline_valid = YES;
}

static BOOL shdw_exc_port_in_baseline(mach_port_t port) {
    if(port == MACH_PORT_NULL) return YES;
    for(mach_msg_type_number_t i = 0; i < shdw_exc_baseline_count; i++) {
        if(shdw_exc_baseline_ports[i] == port) return YES;
    }
    return NO;
}

static kern_return_t (*original_task_get_exception_ports)(task_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t old_handlers, exception_behavior_array_t old_behaviors, exception_flavor_array_t old_flavors);
static kern_return_t replaced_task_get_exception_ports(task_t task, exception_mask_t exception_mask, exception_mask_array_t masks, mach_msg_type_number_t *masksCnt, exception_handler_array_t old_handlers, exception_behavior_array_t old_behaviors, exception_flavor_array_t old_flavors) {
    kern_return_t result = original_task_get_exception_ports(task, exception_mask, masks, masksCnt, old_handlers, old_behaviors, old_flavors);

    // Only filter external self-task queries; internal callers and cross-task
    // queries (task != self) see the raw kernel reply.
    if(result != KERN_SUCCESS || !isCallerExternal() ||
       task != mach_task_self() || !shdw_exc_baseline_valid ||
       !masksCnt || !masks || !old_handlers || !old_behaviors || !old_flavors) {
        return result;
    }

    mach_msg_type_number_t in = *masksCnt, out = 0;
    for(mach_msg_type_number_t i = 0; i < in; i++) {
        if(shdw_exc_port_in_baseline(old_handlers[i])) {
            if(out != i) {
                masks[out] = masks[i];
                old_handlers[out] = old_handlers[i];
                old_behaviors[out] = old_behaviors[i];
                old_flavors[out] = old_flavors[i];
            }
            out++;
        } else if(old_handlers[i] != MACH_PORT_NULL) {
            // Injected handler right: deallocate the ref the kernel handed the
            // caller so hiding it does not leak a port name.
            mach_port_deallocate(mach_task_self(), old_handlers[i]);
        }
    }
    *masksCnt = out;
    return result;
}

// connect: block loopback Frida port-scans (ISS ReverseEngineeringToolsChecker).
// Only external callers are affected; internal Shadow reads pass through.
// Tripwire B: external loopback+listed-port fires shdw_detector_detected("connect")
// before denial so Tier-2 escalates even if detector never touches a JB file path.
static int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int replaced_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(!isCallerExternal()) {
        return original_connect(sockfd, addr, addrlen);
    }

    if(addr) {
        if(addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
            if(sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
                uint16_t port = ntohs(sin->sin_port);
                if(port == 27042 || port == 4444 || port == 2222 ||
                   port == 1337 || port == 44 || port == 22) {
                    shdw_detector_detected("connect");
                    errno = ECONNREFUSED;
                    return -1;
                }
            }
        } else if(addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
            if(IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
                uint16_t port = ntohs(sin6->sin6_port);
                if(port == 27042 || port == 4444 || port == 2222 ||
                   port == 1337 || port == 44 || port == 22) {
                    shdw_detector_detected("connect");
                    errno = ECONNREFUSED;
                    return -1;
                }
            }
        }
    }

    return original_connect(sockfd, addr, addrlen);
}

void shdw_universal_sandbox(SHDWHookSession* hooks) {
    // %init(shadowhook_sandbox);
    // host_get_special_port/task_get_special_port/task_for_pid are raw Mach
    // trap wrappers — the same structural class as syscall/csops (see
    // syscall.x's shadowhook_syscall comment): reached by most callers
    // through a direct/pre-resolved branch into the dyld shared cache rather
    // than a GOT/import slot, so HookKit's auto-cover [INLINE, REBIND] lane
    // can silently fall back to litehook's inline prologue patch, which races
    // any other thread executing through the same hot function. Not
    // reproduced with these three specifically (unlike syscall/csops, which
    // crashed deterministically), but the hazard shape is identical and the
    // cost of being wrong is a process kill — hook them rebind-only, same
    // "skip cleanly when unhookable" tradeoff as the syscall.x fix.
    [hooks hookFunction:sandbox_check withReplacement:replaced_sandbox_check outOldPtr:(void **) &original_sandbox_check];
    [hooks hookFunction:fcntl withReplacement:replaced_fcntl outOldPtr:(void **) &original_fcntl];
    [hooks hookRebindSymbol:@"host_get_special_port" withReplacement:replaced_host_get_special_port outOldPtr:(void **) &original_host_get_special_port];
    [hooks hookRebindSymbol:@"task_get_special_port" withReplacement:replaced_task_get_special_port outOldPtr:(void **) &original_task_get_special_port];
    [hooks hookRebindSymbol:@"task_for_pid" withReplacement:replaced_task_for_pid outOldPtr:(void **) &original_task_for_pid];
    [hooks hookFunction:sigaction withReplacement:replaced_sigaction outOldPtr:(void **) &original_sigaction];

    [hooks hookFunction:execle withReplacement:replaced_execle outOldPtr:NULL];
    [hooks hookFunction:execlp withReplacement:replaced_execlp outOldPtr:NULL];
    [hooks hookFunction:execl withReplacement:replaced_execl outOldPtr:NULL];
    [hooks hookFunction:execve withReplacement:replaced_execve outOldPtr:(void **) &original_execve];
    [hooks hookFunction:execvp withReplacement:replaced_execvp outOldPtr:(void **) &original_execvp];
    [hooks hookFunction:execv withReplacement:replaced_execv outOldPtr:NULL];
    [hooks hookFunction:posix_spawn withReplacement:replaced_posix_spawn outOldPtr:(void **) &original_posix_spawn];
    [hooks hookFunction:posix_spawnp withReplacement:replaced_posix_spawnp outOldPtr:(void **) &original_posix_spawnp];
    resolved_fork = fork;
    if(![hooks hookFunction:fork withReplacement:replaced_fork outOldPtr:(void **) &original_fork]) {
        [hooks hookRebindSymbol:@"fork" withReplacement:replaced_fork outOldPtr:(void **) &original_fork];
    }
    [hooks hookFunction:vfork withReplacement:replaced_vfork outOldPtr:(void **) &original_vfork];

    // Signal aliases: runtime-resolved, skipped cleanly when absent.
    void* sym_signal = shdw_resolve_libsystem("_signal");
    if(sym_signal) {
        [hooks hookFunction:sym_signal withReplacement:replaced_signal outOldPtr:(void **) &original_signal];
    }

    sym_signal = shdw_resolve_libsystem("_bsd_signal");
    if(sym_signal) {
        [hooks hookFunction:sym_signal withReplacement:replaced_bsd_signal outOldPtr:(void **) &original_bsd_signal];
    }

    sym_signal = shdw_resolve_libsystem("____signal_nobind");
    if(sym_signal) {
        [hooks hookFunction:sym_signal withReplacement:replaced___signal_nobind outOldPtr:(void **) &original___signal_nobind];
    }

    sym_signal = shdw_resolve_libsystem("___sigaction");
    if(sym_signal) {
        [hooks hookFunction:sym_signal withReplacement:replaced___sigaction outOldPtr:(void **) &original___sigaction];
    }

    // Misc sibling surfaces: runtime-resolved, skipped cleanly when absent.
    void* sym_misc = shdw_resolve_libsystem("_system");
    if(sym_misc) {
        [hooks hookFunction:sym_misc withReplacement:replaced_system outOldPtr:(void **) &original_system];
    }

    sym_misc = shdw_resolve_libsystem("_popen");
    if(sym_misc) {
        [hooks hookFunction:sym_misc withReplacement:replaced_popen outOldPtr:(void **) &original_popen];
    }

    sym_misc = shdw_resolve_libsystem("_wordexp");
    if(sym_misc) {
        [hooks hookFunction:sym_misc withReplacement:replaced_wordexp outOldPtr:(void **) &original_wordexp];
    }

    sym_misc = shdw_resolve_libsystem("_sandbox_check_by_audit_token");
    if(sym_misc) {
        [hooks hookFunction:sym_misc withReplacement:replaced_sandbox_check_by_audit_token outOldPtr:(void **) &original_sandbox_check_by_audit_token];
    }

    sym_misc = shdw_resolve_libsystem("_task_get_exception_ports");
    if(sym_misc) {
        [hooks hookFunction:sym_misc withReplacement:replaced_task_get_exception_ports outOldPtr:(void **) &original_task_get_exception_ports];
    }

    // connect: runtime-resolved like _signal/_system; absent on exotic OS → skip.
    void* sym_connect = shdw_resolve_libsystem("_connect");
    if(sym_connect) {
        [hooks hookFunction:sym_connect withReplacement:replaced_connect outOldPtr:(void **) &original_connect];
    }
}

void shdw_universal_sandbox_verify(void) {
    // execle/execlp/execl/execv hook with outOldPtr:NULL (no original_* to
    // check); the runtime-resolved signal/system/popen/wordexp/connect aliases
    // are excluded (NULL is expected when the symbol is absent).
    shdw_hook_check_t checks[] = {
        { "sandbox_check", original_sandbox_check },
        { "fcntl", original_fcntl },
        { "host_get_special_port", original_host_get_special_port },
        { "task_get_special_port", original_task_get_special_port },
        { "task_for_pid", original_task_for_pid },
        { "sigaction", original_sigaction },
        { "execve", original_execve },
        { "execvp", original_execvp },
        { "posix_spawn", original_posix_spawn },
        { "posix_spawnp", original_posix_spawnp },
        { "fork", original_fork },
        { "vfork", original_vfork },
    };

    shdw_verify_hooks("sandbox", checks, sizeof(checks) / sizeof(checks[0]));
}

// Symbol policy for the sandbox C-function group (see dyld.x's
// shdw_sym_policy_table): dlsym must resolve every fishhook-rebound sandbox
// export to its replacement for external callers, so the GOT-vs-dlsym
// comparison agrees. Guarded by the original pointer: runtime-resolved
// aliases (signal family, system/popen/wordexp, sandbox_check_by_audit_token,
// task_get_exception_ports) only resolve to their replacement when actually
// installed. The exec family hooks with outOldPtr:NULL (no original_* to
// check) are unconditional — always resolve to their replacement.
typedef struct {
    const char* name;
    void* replacement;
    void* const* original;
} shdw_sandbox_sym_policy_entry_t;

static const shdw_sandbox_sym_policy_entry_t shdw_sandbox_sym_policy_table[] = {
    { "bsd_signal", (void*)&replaced_bsd_signal, (void* const*)&original_bsd_signal },
    { "connect", (void*)&replaced_connect, (void* const*)&original_connect },
    { "execl", (void*)&replaced_execl, NULL },
    { "execle", (void*)&replaced_execle, NULL },
    { "execlp", (void*)&replaced_execlp, NULL },
    { "execv", (void*)&replaced_execv, NULL },
    { "execve", (void*)&replaced_execve, (void* const*)&original_execve },
    { "execvp", (void*)&replaced_execvp, (void* const*)&original_execvp },
    { "fcntl", (void*)&replaced_fcntl, (void* const*)&original_fcntl },
    { "fork", (void*)&replaced_fork, (void* const*)&original_fork },
    { "host_get_special_port", (void*)&replaced_host_get_special_port, (void* const*)&original_host_get_special_port },
    { "popen", (void*)&replaced_popen, (void* const*)&original_popen },
    { "posix_spawn", (void*)&replaced_posix_spawn, (void* const*)&original_posix_spawn },
    { "posix_spawnp", (void*)&replaced_posix_spawnp, (void* const*)&original_posix_spawnp },
    { "sandbox_check", (void*)&replaced_sandbox_check, (void* const*)&original_sandbox_check },
    { "sandbox_check_by_audit_token", (void*)&replaced_sandbox_check_by_audit_token, (void* const*)&original_sandbox_check_by_audit_token },
    { "sigaction", (void*)&replaced_sigaction, (void* const*)&original_sigaction },
    { "signal", (void*)&replaced_signal, (void* const*)&original_signal },
    { "system", (void*)&replaced_system, (void* const*)&original_system },
    { "task_for_pid", (void*)&replaced_task_for_pid, (void* const*)&original_task_for_pid },
    { "task_get_exception_ports", (void*)&replaced_task_get_exception_ports, (void* const*)&original_task_get_exception_ports },
    { "task_get_special_port", (void*)&replaced_task_get_special_port, (void* const*)&original_task_get_special_port },
    { "vfork", (void*)&replaced_vfork, (void* const*)&original_vfork },
    { "wordexp", (void*)&replaced_wordexp, (void* const*)&original_wordexp },
    { "__sigaction", (void*)&replaced___sigaction, (void* const*)&original___sigaction },
    { "__signal_nobind", (void*)&replaced___signal_nobind, (void* const*)&original___signal_nobind },
};

void* shdw_sym_policy_lookup_sandbox(const char* name) {
    if(!name) {
        return NULL;
    }

    for(size_t i = 0; i < sizeof(shdw_sandbox_sym_policy_table) / sizeof(shdw_sandbox_sym_policy_table[0]); i++) {
        if(strcmp(name, shdw_sandbox_sym_policy_table[i].name) == 0) {
            if(shdw_sandbox_sym_policy_table[i].original && *shdw_sandbox_sym_policy_table[i].original == NULL) {
                // Some adapters resolve fork with dlsym(RTLD_DEFAULT). Keep
                // that route covered even when its tiny entrypoint cannot be
                // patched and the app has no fork import to rebind.
                if(strcmp(name, "fork") != 0 || !resolved_fork) {
                    return NULL;  // runtime-resolved symbol not installed
                }
            }

            return shdw_sandbox_sym_policy_table[i].replacement;
        }
    }

    return NULL;
}
