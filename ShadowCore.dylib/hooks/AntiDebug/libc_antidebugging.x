#import "hooks.h"
#import "../../policy/ProcessPolicy.h"
#import "../../policy/EnvironmentPolicy.h"

#import <string.h>
#import <stdlib.h>
#import <sys/resource.h>
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

    // Per-pid queries of a jailbreak daemon must answer ENOENT, the same
    // hiding the KERN_PROC_ALL filter applies to the list (a pid-scanning
    // detector steps the MIB pid by pid).
    if(kind == SHADW_PROC_MIB_PID_OTHER) {
        if(shdw_pid_is_restricted(name[3])) {
            errno = ENOENT;
            return -1;
        }
    } else if(kind == SHADW_PROC_MIB_ARGS2_OTHER) {
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

    // Own KERN_PROCARGS2: the kernel payload is the raw launch argv/envp;
    // rebuild it to agree with the filtered NSProcessInfo/getenv views.
    if(ret == 0 && kind == SHADW_PROC_MIB_ARGS2_SELF && oldp && oldlenp && *oldlenp > (size_t) sizeof(int)) {
        shdw_procargs2_filter(oldp, oldlenp);
    }

    return ret;
}

pid_t (*original_getppid)(void);
pid_t replaced_getppid(void) {
    if(!isCallerExternal()) {
        // Shadow-internal callers get the real parent; the app/detector
        // sees the stock answer for a process without a debugger parent.
        return original_getppid();
    }

    return 1;
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
    int count = original_proc_listpids(type, typeinfo, buffer, buffersize);

    if(count <= 0 || !buffer || !isCallerExternal()) {
        return count;
    }

    return shdw_proc_pids_filtered((pid_t*) buffer, count);
}

int (*original_proc_listallpids)(void* buffer, int buffersize);
int replaced_proc_listallpids(void* buffer, int buffersize) {
    int count = original_proc_listallpids(buffer, buffersize);

    if(count <= 0 || !buffer || !isCallerExternal()) {
        return count;
    }

    return shdw_proc_pids_filtered((pid_t*) buffer, count);
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

    // Cross-API consistency: getppid() reports parent 1, so the own
    // process's BSD info must say the same — a detector comparing
    // getppid() against pbi_ppid would otherwise see the real parent.
    if(ret > 0 && isCallerExternal() && pid == getpid() && flavor == SHADOW_PROC_PIDTBSDINFO
    && buffer && buffersize >= sizeof(struct shdw_proc_bsdinfo_prefix)) {
        ((struct shdw_proc_bsdinfo_prefix*) buffer)->pbi_ppid = 1;
    }

    return ret;
}

void shadowhook_libc_antidebugging(HKSubstitutor* hooks) {
    shdw_libc_install_group(hooks, SHADW_HOOK_GROUP_ANTIDEBUG);
}

void shadowhook_libc_antidebugging_verify(void) {
    shdw_libc_verify_group("libc_antidebugging", SHADW_HOOK_GROUP_ANTIDEBUG);
}
