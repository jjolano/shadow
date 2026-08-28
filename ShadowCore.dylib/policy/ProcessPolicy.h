// Plugin: Policy_Process — registered in SHDWPluginRegistry (HookConfiguration.m)
#define SHDWPolicyProcessPluginID "Policy_Process"

// Process policy shared by the libc and raw-syscall hook surfaces
// (hooks/libc.x, hooks/syscall.x): PID classification (jailbreak daemon by
// executable path) with its caches, KERN_PROC list filtering, MIB
// classification and self-record sanitization. No caller classification
// here — the isCallerExternal() gates and errno handling stay at the hook
// sites.

#import <Foundation/Foundation.h>
#import <sys/types.h>
#import <stddef.h>
#import <sys/sysctl.h>

struct kinfo_proc;

// Classifies a process as restricted (jailbreak daemon) by its executable
// path. proc_pidpath is visible for other pids on iOS; when it fails (EPERM)
// the process cannot be classified and is kept — denying legitimate
// processes would corrupt the process count on stock devices.
//
// Cached keyed on pid + process start time (PID reuse can't inherit a stale
// verdict) with a short TTL (a process can exec a different binary without
// changing its start time). Fixed-size, round-robin eviction — a miss just
// re-classifies, results stay identical. The lock is never held across
// classification: isCPathRestricted is an ObjC call that could re-enter
// hooked code.
BOOL shdw_proc_is_restricted(const struct kinfo_proc* p);

// Uncached pid classification for the per-pid sysctl/sysctlbyname deny
// paths (KERN_PROC_PID / KERN_PROCARGS2 of a jailbreak daemon): the list
// filters already remove restricted processes, so a per-pid query of one
// must answer ENOENT the same way. Un-cached by design — these queries are
// rare, and pid reuse must never inherit a stale verdict. Non-positive pids
// are never classified: pid 0 would resolve via proc_pidpath to our own
// process, which must not be judged here.
BOOL shdw_pid_restricted_uncached(pid_t pid);

// Cached pid classification for libproc enumeration (proc_listpids/
// proc_listallpids/proc_pidinfo): classification is pid-only (libproc hands
// us no start time), so the cache keys on pid alone with a short TTL — a
// reused pid can inherit a stale verdict for at most TTL seconds, and a miss
// just re-classifies, so results stay identical. Same fail-open rule as the
// sysctl path.
BOOL shdw_pid_is_restricted(pid_t pid);

// Original-call shape used by the KERN_PROC_ALL filter below
// (sysctl(2)-compatible argument order).
typedef int (*shdw_sysctl_proc_fn)(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen);

// Filtered KERN_PROC_ALL enumeration: two-phase size/full query with one
// churn retry, restricted processes removed, self trace flags cleared.
// Stock sysctl size semantics are preserved (size-only query → filtered
// byte count in *oldlenp; short buffer → ENOMEM with the required size in
// *oldlenp).
//
// `orig` is the adapter's own original call (original_sysctl for the libc
// hook, an original_syscall(SYS_sysctl, ...) forward for the raw surface).
// `reentrant` YES for the raw surface, whose original calls can re-enter
// the (possibly __syscall-delegating) dispatch — the filter then sets the
// in-progress flag that the dispatch checks (shdw_proc_all_in_progress)
// before applying this policy again.
int shdw_proc_all_filtered(shdw_sysctl_proc_fn orig, void* oldp, size_t* oldlenp, BOOL reentrant);

// YES while a reentrant KERN_PROC_ALL filter is inside its original calls
// (see shdw_proc_all_filtered).
BOOL shdw_proc_all_in_progress(void);

// Compacts restricted pids out of a proc_listpids/proc_listallpids result
// buffer in place. The buffer holds pid_t entries; returns the filtered
// count (0 when everything was removed — the caller reads that as "no
// processes", the same hiding the sysctl filter achieves).
int shdw_proc_pids_filtered(pid_t* pids, int count);

// Clears the trace flags a debugger leaves on our own record.
void shdw_proc_sanitize_self_trace_flags(struct kinfo_proc* p);

// Full self-record sanitization: trace flags cleared AND kp_eproc.e_ppid
// forced to 1 — cross-API consistency: getppid() reports parent 1, so the
// own record must say the same (a detector comparing getppid() against
// kp_eproc.e_ppid would otherwise see the real parent (debugger, host app)).
void shdw_proc_sanitize_self_record(struct kinfo_proc* p);

// Classifies a sysctl MIB as one of the process surfaces. NONE for
// anything else (including malformed shapes like KERN_PROC_PID with a
// non-positive pid, which must pass through untouched). Safe for NULL name
// and short namelen.
typedef enum {
    SHADW_PROC_MIB_NONE = 0,
    SHADW_PROC_MIB_ALL,         // {CTL_KERN, KERN_PROC, KERN_PROC_ALL[, 0]}
    SHADW_PROC_MIB_PID_SELF,    // {CTL_KERN, KERN_PROC, KERN_PROC_PID, self}
    SHADW_PROC_MIB_PID_OTHER,   // {CTL_KERN, KERN_PROC, KERN_PROC_PID, >0, != self}
    SHADW_PROC_MIB_ARGS2_SELF,  // {CTL_KERN, KERN_PROCARGS2, self}
    SHADW_PROC_MIB_ARGS2_OTHER, // {CTL_KERN, KERN_PROCARGS2, >0, != self}
    SHADW_PROC_MIB_BOOTARGS,    // {CTL_KERN, KERN_BOOTARGS}
} shdw_proc_mib_kind_t;

shdw_proc_mib_kind_t shdw_proc_mib_kind(const int* name, u_int namelen);

// kern.bootargs answer for external callers: stock devices report an empty
// boot-args string, while jailbreak boot flags (amfi_get_out_of_my_way=1,
// debug=..., -v) are a direct jailbreak tell. Answered WITHOUT an original
// call so the size-only probe and the data query agree — a real size would
// leak the boot flags' length even with the data filtered. Stock string-node
// semantics: empty string is one NUL byte.
// Returns 0 on success; -1 with errno ENOMEM when the caller's buffer is
// too short (required size still stored in *oldlenp), EFAULT when oldlenp
// is NULL. Callers divert only read queries (newp == NULL).
int shdw_bootargs_filtered(void* oldp, size_t* oldlenp);