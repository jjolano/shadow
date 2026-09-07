#import "UniversalHooks.h"
#import "../../policy/ProcessPolicy.h"
#import "../../policy/EnvironmentPolicy.h"

#import <string.h>
#import <stdlib.h>
#import <sys/resource.h>
#import <sys/utsname.h>
#import <sys/wait.h>
#import <ifaddrs.h>
#import <unistd.h>

int (*original_ptrace)(int _request, pid_t _pid, caddr_t _addr, int _data);
int replaced_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data) {
    if(_request == PT_DENY_ATTACH) {
        return 0;
    }

    return original_ptrace(_request, _pid, _addr, _data);
}

// libproc.h isn't shipped in the theos SDK; declare the symbols we need
// (all stable libSystem exports).
extern int proc_pidpath(int pid, void* buffer, uint32_t buffersize);
extern int proc_pidpath_audittoken(audit_token_t* token, void* buffer, uint32_t buffersize);
extern int proc_listpids(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize);
extern int proc_listallpids(void* buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void* buffer, int buffersize);

// libproc.h isn't shipped in the theos SDK either, so declare the two pieces
// of the PROC_PIDTBSDINFO query we mask. proc_bsdinfo is a stable public ABI;
// the prefix layout matches it exactly (pbi_ppid at offset 0x10). Only that
// field is ever written.
#define SHADOW_PROC_PIDTBSDINFO 3

struct shdw_proc_bsdinfo_prefix {
    uint32_t pbi_flags;    /* 0x00 */
    uint32_t pbi_status;   /* 0x04 */
    uint32_t pbi_xstatus;  /* 0x08 */
    uint32_t pbi_pid;      /* 0x0c */
    uint32_t pbi_ppid;     /* 0x10 */
};

// Process classification/filtering shared with syscall.x lives in
// policy/ProcessPolicy.m: the kinfo cache, the filtered KERN_PROC_ALL
// enumeration, the libproc pid filter and the MIB classification
// (shdw_proc_mib_kind) that drives this hook's branches.
int (*original_sysctl)(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);

int replaced_sysctl(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    if(name == NULL || namelen == 0) {
        return original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }

    shdw_proc_mib_kind_t kind = shdw_proc_mib_kind(name, namelen);

    // kern.bootargs: answered directly (empty string, stock semantics) —
    // see shdw_bootargs_filtered. Setting boot args (newp) passes through.
    if(kind == SHADW_PROC_MIB_BOOTARGS && newp == NULL) {
        return shdw_bootargs_filtered(oldp, oldlenp);
    }

    // Per-pid queries of a jailbreak daemon must answer ENOENT, the same
    // hiding the KERN_PROC_ALL filter applies to the list (a pid-scanning
    // detector steps the MIB pid by pid).
    if(kind == SHADW_PROC_MIB_PID_OTHER) {
        if(shdw_pid_is_restricted(name[3])) {
            errno = ENOENT;
            return -1;
        }
    } else if(kind == SHADW_PROC_MIB_ARGS2_OTHER || kind == SHADW_PROC_MIB_ARGS_OTHER) {
        if(shdw_pid_is_restricted(name[2])) {
            errno = ENOENT;
            return -1;
        }
    }

    int ret;

    if(kind == SHADW_PROC_MIB_ALL && newp == NULL && oldlenp != NULL) {
        // Filtered KERN_PROC_ALL enumeration: restricted processes removed,
        // self trace flags cleared, stock size semantics preserved. The
        // libc surface's original calls cannot re-enter the raw-syscall
        // dispatch, so no in-progress guard (reentrant = NO).
        ret = shdw_proc_all_filtered(original_sysctl, oldp, oldlenp, NO);
    } else {
        ret = original_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }

    // Remove trace flags from our own process record — only on valid success
    // and only when the caller's buffer actually carries the record.
    if(ret == 0 && kind == SHADW_PROC_MIB_PID_SELF && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
        shdw_proc_sanitize_self_record((struct kinfo_proc*) oldp);
    }

    // Own KERN_PROCARGS(2): the kernel payload is the raw launch argv/envp;
    // rebuild it to agree with the filtered NSProcessInfo/getenv views.
    if(ret == 0 && (kind == SHADW_PROC_MIB_ARGS2_SELF || kind == SHADW_PROC_MIB_ARGS_SELF) && oldp && oldlenp && *oldlenp > (size_t) sizeof(int)) {
        shdw_procargs2_filter(oldp, oldlenp);
    }

    return ret;
}

pid_t (*original_getppid)(void);
static pid_t (*resolved_getppid)(void);
pid_t replaced_getppid(void) {
    if(!isCallerExternal()) {
        // Shadow-internal callers get the real parent; the app/detector
        // sees the stock answer for a process without a debugger parent.
        pid_t (*getppid_impl)(void) = original_getppid ?: resolved_getppid;
        return getppid_impl ? getppid_impl() : 1;
    }

    return 1;
}

// getuid/geteuid: App Store apps never run as root — uid 0 in-process is a
// jailbreak artifact detectors check directly (BAT RootUser). Answer the
// stock mobile user (501) to external callers; Shadow-internal callers keep
// truth. Same shape as replaced_getppid above (rebind lane + late-image
// replay via the resolved fallback).
uid_t (*original_getuid)(void);
static uid_t (*resolved_getuid)(void);
uid_t replaced_getuid(void) {
    if(!isCallerExternal()) {
        uid_t (*getuid_impl)(void) = original_getuid ?: resolved_getuid;
        return getuid_impl ? getuid_impl() : 0;
    }

    return 501;
}

uid_t (*original_geteuid)(void);
static uid_t (*resolved_geteuid)(void);
uid_t replaced_geteuid(void) {
    if(!isCallerExternal()) {
        uid_t (*geteuid_impl)(void) = original_geteuid ?: resolved_geteuid;
        return geteuid_impl ? geteuid_impl() : 0;
    }

    return 501;
}

// getgid/getegid: cross-API consistency with the uid fake above. On a rootful
// jailbreak the app runs gid 0 as well as uid 0; faking uid->501 while leaving
// gid 0 manufactures a (uid=501, gid=0) pair stock iOS never produces — a
// contradiction a detector reads directly. Answer the stock mobile group (501)
// to external callers so the identity is coherent; Shadow-internal callers keep
// truth. On rootless the process is already 501:501 and both are inert. Same
// rebind lane + late-image replay shape as getuid/getppid.
gid_t (*original_getgid)(void);
static gid_t (*resolved_getgid)(void);
gid_t replaced_getgid(void) {
    if(!isCallerExternal()) {
        gid_t (*getgid_impl)(void) = original_getgid ?: resolved_getgid;
        return getgid_impl ? getgid_impl() : 0;
    }

    return 501;
}

gid_t (*original_getegid)(void);
static gid_t (*resolved_getegid)(void);
gid_t replaced_getegid(void) {
    if(!isCallerExternal()) {
        gid_t (*getegid_impl)(void) = original_getegid ?: resolved_getegid;
        return getegid_impl ? getegid_impl() : 0;
    }

    return 501;
}

// issetugid: under DYLD injection (systemhook / DYLD_INSERT_LIBRARIES) this
// commonly returns 1 (tainted environment). Shadow scrubs every DYLD_* env
// channel to look clean, so a leftover issetugid()==1 is a standalone
// injection tell that contradicts the scrubbed environment. Answer 0 (stock
// untainted) to external callers; internal callers keep truth.
int (*original_issetugid)(void);
static int (*resolved_issetugid)(void);
int replaced_issetugid(void) {
    if(!isCallerExternal()) {
        int (*issetugid_impl)(void) = original_issetugid ?: resolved_issetugid;
        return issetugid_impl ? issetugid_impl() : 0;
    }

    return 0;
}

// getrusage(RUSAGE_CHILDREN): a detector spawns a child to test execution
// and measures its CPU usage to infer a jailbreak. Zero the child-accounting
// fields for external callers so the probe sees a child that never ran.
// RUSAGE_SELF is untouched — it is the caller's own accounting and carries
// no jailbreak signal.
int (*original_getrusage)(int who, struct rusage* usage);
int replaced_getrusage(int who, struct rusage* usage) {
    int result = original_getrusage(who, usage);

    if(result == 0 && isCallerExternal() && who == RUSAGE_CHILDREN && usage) {
        memset(usage, 0, sizeof(*usage));
    }

    return result;
}

// Shared child-accounting zeroing for the wait family (wait4/wait3/waitpid
// with rusage, waitid with siginfo): external callers never see a real
// child's resource usage — same stock shape as the getrusage(CHILDREN)
// hook above (a child that never ran). Sandboxed app spawns already fail,
// but a successful wait (e.g. reaping a Foundation-spawned helper) must
// still agree with the zeroed getrusage view.
static void shdw_wait_zero_rusage(struct rusage* usage) {
    if(usage) {
        memset(usage, 0, sizeof(*usage));
    }
}

// wait4/waitpid/wait3: only the rusage OUT-param is sanitized, never the
// pid/status contract. Zeroing a post-success out-param cannot contradict
// the reaping semantics the caller relies on; child-pid identities pass
// through untouched. Continuations live in libc.x's NULL-original cells
// (void* shdw_libc_null_original answers the pre-hook dlsym captured at
// install; same shape as the sandbox resolved_fork fallback) — read per
// call, never cached here, so a late install is picked up without a stale copy.
void* shdw_libc_null_original(const char* symbol);

static pid_t shdw_wait4_via(pid_t pid, int* status, int options, struct rusage* rusage) {
    void* fn = shdw_libc_null_original("wait4");
    return fn ? ((pid_t (*)(pid_t, int*, int, struct rusage*))fn)(pid, status, options, rusage) : -1;
}

static pid_t shdw_waitpid_via(pid_t pid, int* status, int options) {
    void* fn = shdw_libc_null_original("waitpid");
    return fn ? ((pid_t (*)(pid_t, int*, int))fn)(pid, status, options) : -1;
}

static pid_t shdw_wait3_via(int* status, int options, struct rusage* rusage) {
    void* fn = shdw_libc_null_original("wait3");
    return fn ? ((pid_t (*)(int*, int, struct rusage*))fn)(status, options, rusage) : -1;
}

static int shdw_waitid_via(idtype_t idtype, id_t id, siginfo_t* infop, int options) {
    void* fn = shdw_libc_null_original("waitid");
    return fn ? ((int (*)(idtype_t, id_t, siginfo_t*, int))fn)(idtype, id, infop, options) : -1;
}

pid_t replaced_wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
    pid_t result = shdw_wait4_via(pid, status, options, rusage);

    if(result > 0 && rusage && isCallerExternal()) {
        shdw_wait_zero_rusage(rusage);
    }

    return result;
}

pid_t replaced_waitpid(pid_t pid, int* status, int options) {
    return shdw_waitpid_via(pid, status, options);
}

pid_t replaced_wait3(int* status, int options, struct rusage* rusage) {
    pid_t result = shdw_wait3_via(status, options, rusage);

    if(result > 0 && rusage && isCallerExternal()) {
        shdw_wait_zero_rusage(rusage);
    }

    return result;
}

// waitid(idtype, id, infop, options): Darwin's siginfo_t carries NO
// child-CPU-time fields (unlike Linux si_utime/si_stime), so there is no
// resource snapshot to sanitize — pass through. Hooked only to keep the
// symbol in the dlsym policy table (GOT-vs-dlsym agreement), same as the
// waitpid pass-through above.
int replaced_waitid(idtype_t idtype, id_t id, siginfo_t* infop, int options) {
    return shdw_waitid_via(idtype, id, infop, options);
}

// getrlimit: pass-through (conservative). RLIMIT probes are not a reliable
// jailbreak signal — legitimate apps set/read limits routinely — so no
// fabrication here; the hook exists for coverage and to keep the symbol in
// the dlsym policy table (GOT-vs-dlsym agreement).
int (*original_getrlimit)(int resource, struct rlimit* rlp);
int replaced_getrlimit(int resource, struct rlimit* rlp) {
    return original_getrlimit(resource, rlp);
}

// libproc enumeration (proc_listpids/proc_listallpids/proc_pidinfo) is the
// second process-list surface after sysctl KERN_PROC: detectors enumerate
// pids and query per-pid details to find jailbreak daemons. The sysctl hook
// filters the kinfo_proc list; these hooks filter the libproc views of the
// same processes. Classification and the pid-list compaction live in
// policy/ProcessPolicy.m (shdw_pid_is_restricted / shdw_proc_pids_filtered).

int (*original_proc_listpids)(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize);
int replaced_proc_listpids(uint32_t type, uint32_t typeinfo, void* buffer, int buffersize) {
    // NULL-buffer probe: the caller asks for the COUNT (or just validates
    // the args) without handing us a buffer. Filtered size semantics match
    // KERN_PROC_ALL (ProcessPolicy.m): compute the filtered count from a
    // real enumeration so the two channels agree on the same daemon-free
    // number. Fail open to the raw count on any error.
    if(!buffer || buffersize <= 0) {
        int raw = original_proc_listpids(type, typeinfo, buffer, buffersize);

        if(raw <= 0 || !isCallerExternal()) {
            return raw;
        }

        int cap = raw;
        pid_t* tmp = malloc((size_t)cap * sizeof(pid_t));

        if(!tmp) {
            return raw;
        }

        int got = original_proc_listpids(type, typeinfo, tmp, cap * (int)sizeof(pid_t));
        int filtered = got > 0 ? shdw_proc_pids_filtered(tmp, got) : raw;
        free(tmp);
        return got > 0 ? filtered : raw;
    }

    int count = original_proc_listpids(type, typeinfo, buffer, buffersize);

    if(count <= 0 || !isCallerExternal()) {
        return count;
    }

    return shdw_proc_pids_filtered((pid_t*) buffer, count);
}

int (*original_proc_listallpids)(void* buffer, int buffersize);
int replaced_proc_listallpids(void* buffer, int buffersize) {
    if(!buffer || buffersize <= 0) {
        int raw = original_proc_listallpids(buffer, buffersize);

        if(raw <= 0 || !isCallerExternal()) {
            return raw;
        }

        int cap = raw;
        pid_t* tmp = malloc((size_t)cap * sizeof(pid_t));

        if(!tmp) {
            return raw;
        }

        int got = original_proc_listallpids(tmp, cap * (int)sizeof(pid_t));
        int filtered = got > 0 ? shdw_proc_pids_filtered(tmp, got) : raw;
        free(tmp);
        return got > 0 ? filtered : raw;
    }

    int count = original_proc_listallpids(buffer, buffersize);

    if(count <= 0 || !isCallerExternal()) {
        return count;
    }

    return shdw_proc_pids_filtered((pid_t*) buffer, count);
}

int (*original_proc_pidpath)(int pid, void* buffer, uint32_t buffersize);
int replaced_proc_pidpath(int pid, void* buffer, uint32_t buffersize) {
    if(isCallerExternal() && shdw_pid_is_restricted(pid)) {
        // Jailbreak daemon: deny the per-pid path query the same way
        // proc_pidinfo denies per-pid inspection. EPERM matches what an
        // unprivileged caller sees for processes it may not inspect
        // (same errno as replaced_proc_pidinfo above).
        errno = EPERM;
        return 0;
    }

    return original_proc_pidpath(pid, buffer, buffersize);
}

// proc_pidpath_audittoken: same policy as proc_pidpath (EPERM for a
// restricted process). The audit_token_t (mach/message.h, via hooks.h's
// <mach/mach.h>) carries the pid at val[4] (AU_TOKEN_PID) — same as the
// sandbox_check_by_audit_token hook in sandbox.x.
int (*original_proc_pidpath_audittoken)(audit_token_t* token, void* buffer, uint32_t buffersize);
int replaced_proc_pidpath_audittoken(audit_token_t* token, void* buffer, uint32_t buffersize) {
    if(isCallerExternal() && token && shdw_pid_is_restricted((pid_t)token->val[4])) {
        errno = EPERM;
        return 0;
    }

    return original_proc_pidpath_audittoken(token, buffer, buffersize);
}

int (*original_proc_pidinfo)(int pid, int flavor, uint64_t arg, void* buffer, int buffersize);
int replaced_proc_pidinfo(int pid, int flavor, uint64_t arg, void* buffer, int buffersize) {
    if(isCallerExternal() && shdw_pid_is_restricted(pid)) {
        // Jailbreak daemon: deny the per-pid query the same way the pid
        // list filters deny enumeration. EPERM matches what an unprivileged
        // caller sees for processes it may not inspect.
        errno = EPERM;
        return 0;
    }

    int ret = original_proc_pidinfo(pid, flavor, arg, buffer, buffersize);

    // Cross-API consistency: getppid() reports parent 1 and the sysctl
    // self-record is fully sanitized (trace flags + ppid), so the own
    // PROC_PIDTBSDINFO must say the same — a detector comparing channels
    // must see one agreed record. pbi_flags shares the proc.h P_TRACED/
    // P_SELECT bits; mask the same pair ProcessPolicy.m clears.
    if(ret > 0 && isCallerExternal() && pid == getpid() && flavor == SHADOW_PROC_PIDTBSDINFO
    && buffer && buffersize >= (int)sizeof(struct shdw_proc_bsdinfo_prefix)) {
        struct shdw_proc_bsdinfo_prefix* bsd = (struct shdw_proc_bsdinfo_prefix*) buffer;
        bsd->pbi_flags &= ~(0x00000040u | 0x00000800u);
        bsd->pbi_ppid = 1;
    }

    return ret;
}

// kill: signal-based daemon liveness probe (kill(pid, 0)). A restricted
// pid answers ESRCH — the stock "no such process" a filtered-out daemon
// must present so kill(0-probe) agrees with the sysctl/libproc lists.
// Self-signals pass through (an app signaling itself is legitimate);
// restricted non-self pids are rejected BEFORE the original runs (never
// deliver-then-fail). Fail open for unclassifiable pids.
int (*original_kill)(pid_t pid, int sig);
int replaced_kill(pid_t pid, int sig) {
    if(isCallerExternal() && pid > 0 && pid != getpid() && shdw_pid_is_restricted(pid)) {
        errno = ESRCH;
        return -1;
    }

    return original_kill(pid, sig);
}

// uname: stock answer, no fabrication. The kernel version carries no
// jailbreak signal on its own (detectors pair it with other evidence),
// and forging it would contradict every other version channel
// (NSProcessInfo, UIDevice, dyld). Hooked only to keep the symbol in the
// dlsym policy table (GOT-vs-dlsym agreement) — body is pass-through.
int (*original_uname)(struct utsname* buf);
int replaced_uname(struct utsname* buf) {
    return original_uname(buf);
}

// getifaddrs: pass-through (conservative). Interface enumeration is not a
// file-evidence channel — jailbreaks add no interfaces stock lacks, and
// filtering a real interface would break networking. Hooked only for
// dlsym-policy agreement, like getrlimit above.
int (*original_getifaddrs)(struct ifaddrs** ifap);
int replaced_getifaddrs(struct ifaddrs** ifap) {
    return original_getifaddrs(ifap);
}

// ioctl: pass-through (conservative). The request space is unbounded and
// no verified JB ioctl signature is probe-gated, so any filtering here
// would be speculation — a wrong deny breaks drivers. Hooked only for
// dlsym-policy agreement.
int (*original_ioctl)(int fd, unsigned long request, ...);
int replaced_ioctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void* argp = va_arg(args, void*);
    va_end(args);
    return original_ioctl(fd, request, argp);
}

void shdw_universal_antidebugging_rebind_image(SHDWHookSession* hooks, const void* imageHeader) {
    if(!imageHeader) return;
    if(original_sysctl)
        [hooks hookRebindSymbol:@"sysctl" withReplacement:replaced_sysctl outOldPtr:NULL inCallerImage:imageHeader];
    if(!resolved_getppid)
        resolved_getppid = dlsym(RTLD_DEFAULT, "getppid");
    if(original_getppid || resolved_getppid)
        [hooks hookRebindSymbol:@"getppid" withReplacement:replaced_getppid outOldPtr:NULL inCallerImage:imageHeader];
    if(!resolved_getuid)
        resolved_getuid = dlsym(RTLD_DEFAULT, "getuid");
    if(original_getuid || resolved_getuid)
        [hooks hookRebindSymbol:@"getuid" withReplacement:replaced_getuid outOldPtr:NULL inCallerImage:imageHeader];
    if(!resolved_geteuid)
        resolved_geteuid = dlsym(RTLD_DEFAULT, "geteuid");
    if(original_geteuid || resolved_geteuid)
        [hooks hookRebindSymbol:@"geteuid" withReplacement:replaced_geteuid outOldPtr:NULL inCallerImage:imageHeader];
    if(!resolved_getgid)
        resolved_getgid = dlsym(RTLD_DEFAULT, "getgid");
    if(original_getgid || resolved_getgid)
        [hooks hookRebindSymbol:@"getgid" withReplacement:replaced_getgid outOldPtr:NULL inCallerImage:imageHeader];
    if(!resolved_getegid)
        resolved_getegid = dlsym(RTLD_DEFAULT, "getegid");
    if(original_getegid || resolved_getegid)
        [hooks hookRebindSymbol:@"getegid" withReplacement:replaced_getegid outOldPtr:NULL inCallerImage:imageHeader];
    if(!resolved_issetugid)
        resolved_issetugid = dlsym(RTLD_DEFAULT, "issetugid");
    if(original_issetugid || resolved_issetugid)
        [hooks hookRebindSymbol:@"issetugid" withReplacement:replaced_issetugid outOldPtr:NULL inCallerImage:imageHeader];
}

void shdw_universal_antidebugging(SHDWHookSession* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_ANTIDEBUG);
}

void shdw_universal_antidebugging_verify(void) {
    shdw_libc_verify_group("libc_antidebugging", SHADW_HOOK_GROUP_ANTIDEBUG);
}
