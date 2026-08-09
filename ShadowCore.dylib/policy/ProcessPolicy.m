// Process policy. The kinfo cache, the filtered KERN_PROC_ALL enumeration
// and the libproc pid cache came from the near-identical copies in
// hooks/libc.x and hooks/syscall.x; the raw surface additionally
// re-entrancy-guards its original calls (kept behind the `reentrant`
// parameter so the per-surface semantics are unchanged).

#import "ProcessPolicy.h"

#import "../hooks/hooks.h"

#import <string.h>
#import <stdlib.h>
#import <os/lock.h>
#import <time.h>
#import <sys/sysctl.h>

// libproc.h isn't shipped in the theos SDK; declare the symbols we need
// (all stable libSystem exports).
extern int proc_pidpath(int pid, void* buffer, uint32_t buffersize);

// --- kinfo_proc classification cache (pid + process start time) -----------

#define SHADW_PROC_CACHE_SIZE 32
#define SHADW_PROC_CACHE_TTL 5  // seconds

typedef struct {
    pid_t pid;
    time_t start_sec;        // kp_proc.p_starttime
    suseconds_t start_usec;
    time_t stamp;            // time(NULL) at fill
    BOOL restricted;
} shdw_proc_cache_entry_t;

static shdw_proc_cache_entry_t shdw_proc_cache[SHADW_PROC_CACHE_SIZE];
static NSUInteger shdw_proc_cache_next = 0;
static os_unfair_lock shdw_proc_cache_lock = OS_UNFAIR_LOCK_INIT;

BOOL shdw_proc_is_restricted(const struct kinfo_proc* p) {
    pid_t pid = p->kp_proc.p_pid;
    time_t start_sec = p->kp_proc.p_starttime.tv_sec;
    suseconds_t start_usec = p->kp_proc.p_starttime.tv_usec;
    time_t now = time(NULL);

    os_unfair_lock_lock(&shdw_proc_cache_lock);

    for(NSUInteger i = 0; i < SHADW_PROC_CACHE_SIZE; i++) {
        const shdw_proc_cache_entry_t* e = &shdw_proc_cache[i];

        if(e->pid == pid
        && e->start_sec == start_sec
        && e->start_usec == start_usec
        && now - e->stamp < SHADW_PROC_CACHE_TTL) {
            BOOL verdict = e->restricted;
            os_unfair_lock_unlock(&shdw_proc_cache_lock);
            return verdict;
        }
    }

    os_unfair_lock_unlock(&shdw_proc_cache_lock);

    char path[PATH_MAX];
    BOOL restricted = NO;

    if(proc_pidpath(pid, path, sizeof(path)) > 0) {
        restricted = [_shadow isCPathRestricted:path];
    }

    os_unfair_lock_lock(&shdw_proc_cache_lock);

    NSUInteger slot = shdw_proc_cache_next;
    shdw_proc_cache_next = (shdw_proc_cache_next + 1) % SHADW_PROC_CACHE_SIZE;

    shdw_proc_cache[slot].pid = pid;
    shdw_proc_cache[slot].start_sec = start_sec;
    shdw_proc_cache[slot].start_usec = start_usec;
    shdw_proc_cache[slot].stamp = now;
    shdw_proc_cache[slot].restricted = restricted;

    os_unfair_lock_unlock(&shdw_proc_cache_lock);
    return restricted;
}

BOOL shdw_pid_restricted_uncached(pid_t pid) {
    if(pid <= 0) {
        return NO;
    }

    char path[PATH_MAX];

    if(proc_pidpath(pid, path, sizeof(path)) <= 0) {
        return NO;  // unclassifiable: keep (same fail-open rule as the caches)
    }

    return [_shadow isCPathRestricted:path];
}

// --- libproc pid classification cache (pid only) ---------------------------
// Classification is pid-only (libproc hands us no start time), so the cache
// keys on pid alone with a short TTL — a reused pid can inherit a stale
// verdict for at most TTL seconds, and a miss just re-classifies, so results
// stay identical. Same fail-open rule as the sysctl path: an unclassifiable
// process (proc_pidpath EPERM) is kept — denying legitimate processes would
// corrupt process counts on stock devices. The lock is never held across
// classification (isCPathRestricted is an ObjC call that could re-enter
// hooked code).

#define SHADW_PID_CACHE_SIZE 32
#define SHADW_PID_CACHE_TTL 5  // seconds

typedef struct {
    pid_t pid;
    time_t stamp;
    BOOL restricted;
} shdw_pid_cache_entry_t;

static shdw_pid_cache_entry_t shdw_pid_cache[SHADW_PID_CACHE_SIZE];
static NSUInteger shdw_pid_cache_next = 0;
static os_unfair_lock shdw_pid_cache_lock = OS_UNFAIR_LOCK_INIT;

BOOL shdw_pid_is_restricted(pid_t pid) {
    time_t now = time(NULL);

    os_unfair_lock_lock(&shdw_pid_cache_lock);

    for(NSUInteger i = 0; i < SHADW_PID_CACHE_SIZE; i++) {
        const shdw_pid_cache_entry_t* e = &shdw_pid_cache[i];

        if(e->pid == pid && now - e->stamp < SHADW_PID_CACHE_TTL) {
            BOOL verdict = e->restricted;
            os_unfair_lock_unlock(&shdw_pid_cache_lock);
            return verdict;
        }
    }

    os_unfair_lock_unlock(&shdw_pid_cache_lock);

    char path[PATH_MAX];
    BOOL restricted = NO;

    if(proc_pidpath(pid, path, sizeof(path)) > 0) {
        restricted = [_shadow isCPathRestricted:path];
    }

    os_unfair_lock_lock(&shdw_pid_cache_lock);

    NSUInteger slot = shdw_pid_cache_next;
    shdw_pid_cache_next = (shdw_pid_cache_next + 1) % SHADW_PID_CACHE_SIZE;

    shdw_pid_cache[slot].pid = pid;
    shdw_pid_cache[slot].stamp = now;
    shdw_pid_cache[slot].restricted = restricted;

    os_unfair_lock_unlock(&shdw_pid_cache_lock);
    return restricted;
}

int shdw_proc_pids_filtered(pid_t* pids, int count) {
    int out = 0;

    for(int i = 0; i < count; i++) {
        if(shdw_pid_is_restricted(pids[i])) {
            continue;  // jailbreak daemon: removed from the list
        }

        if(out != i) {
            pids[out] = pids[i];
        }

        out++;
    }

    return out;
}

// --- filtered KERN_PROC_ALL enumeration ------------------------------------

static _Thread_local BOOL shdw_proc_all_in_progress_flag = NO;

BOOL shdw_proc_all_in_progress(void) {
    return shdw_proc_all_in_progress_flag;
}

int shdw_proc_all_filtered(shdw_sysctl_proc_fn orig, void* oldp, size_t* oldlenp, BOOL reentrant) {
    int procMIB[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };

    if(reentrant) {
        shdw_proc_all_in_progress_flag = YES;
    }

    size_t capacity = 0;
    int ret = orig(procMIB, 3, NULL, &capacity, NULL, 0);

    if(ret != 0) {
        if(reentrant) {
            shdw_proc_all_in_progress_flag = NO;
        }
        return ret;  // kernel owns the error and *oldlenp
    }

    // Slack for process churn between the size and full queries.
    capacity += sizeof(struct kinfo_proc) * 8;

    struct kinfo_proc* procs = malloc(capacity);

    if(!procs) {
        errno = ENOMEM;
        if(reentrant) {
            shdw_proc_all_in_progress_flag = NO;
        }
        return -1;
    }

    size_t actual = capacity;
    ret = orig(procMIB, 3, procs, &actual, NULL, 0);

    if(ret != 0 && errno == ENOMEM) {
        // Churn outgrew the first buffer: retry once with the kernel's size.
        free(procs);
        capacity = actual;
        procs = malloc(capacity);

        if(!procs) {
            errno = ENOMEM;
            if(reentrant) {
                shdw_proc_all_in_progress_flag = NO;
            }
            return -1;
        }

        actual = capacity;
        ret = orig(procMIB, 3, procs, &actual, NULL, 0);
    }

    if(ret != 0) {
        free(procs);
        if(reentrant) {
            shdw_proc_all_in_progress_flag = NO;
        }
        return ret;
    }

    int count = (int)(actual / sizeof(struct kinfo_proc));
    int out = 0;

    for(int i = 0; i < count; i++) {
        struct kinfo_proc* p = &procs[i];

        if(p->kp_proc.p_pid == getpid()) {
            // Never report our own trace flags; and cross-API consistency:
            // getppid() reports parent 1, so the own record must say the
            // same (see the per-pid hooks).
            shdw_proc_sanitize_self_record(p);
        } else if(shdw_proc_is_restricted(p)) {
            continue;  // jailbreak daemon: removed from the list
        }

        if(out != i) {
            procs[out] = procs[i];
        }

        out++;
    }

    size_t needed = (size_t) out * sizeof(struct kinfo_proc);

    if(oldp == NULL) {
        // Size-only query: report the filtered byte count.
        *oldlenp = needed;
        free(procs);
        if(reentrant) {
            shdw_proc_all_in_progress_flag = NO;
        }
        return 0;
    }

    if(*oldlenp < needed) {
        // Short buffer: stock sysctl semantics (ENOMEM + required size).
        *oldlenp = needed;
        free(procs);
        errno = ENOMEM;
        if(reentrant) {
            shdw_proc_all_in_progress_flag = NO;
        }
        return -1;
    }

    memcpy(oldp, procs, needed);
    *oldlenp = needed;
    free(procs);
    if(reentrant) {
        shdw_proc_all_in_progress_flag = NO;
    }
    return 0;
}

// --- self-record sanitization ----------------------------------------------

void shdw_proc_sanitize_self_trace_flags(struct kinfo_proc* p) {
    // CS_DEBUGGED-adjacent kernel state: never report our own trace flags.
    p->kp_proc.p_flag &= ~P_TRACED;
    p->kp_proc.p_flag &= ~P_SELECT;
}

void shdw_proc_sanitize_self_record(struct kinfo_proc* p) {
    shdw_proc_sanitize_self_trace_flags(p);
    p->kp_eproc.e_ppid = 1;
}

// --- sysctl MIB classification ---------------------------------------------

shdw_proc_mib_kind_t shdw_proc_mib_kind(const int* name, u_int namelen) {
    if(!name || namelen < 3) {
        return SHADW_PROC_MIB_NONE;
    }

    if(name[0] != CTL_KERN) {
        return SHADW_PROC_MIB_NONE;
    }

    if(name[1] == KERN_PROC) {
        if(name[2] == KERN_PROC_ALL) {
            // KERN_PROC_ALL is a 3-element MIB (some callers append a
            // legacy 4th zero element).
            if(namelen == 3 || (namelen == 4 && name[3] == 0)) {
                return SHADW_PROC_MIB_ALL;
            }

            return SHADW_PROC_MIB_NONE;
        }

        if(name[2] == KERN_PROC_PID && namelen == 4) {
            if(name[3] == (int) getpid()) {
                return SHADW_PROC_MIB_PID_SELF;
            }

            if(name[3] > 0) {
                return SHADW_PROC_MIB_PID_OTHER;
            }

            // Non-positive pid: not our record and not a classifiable
            // other — pass through untouched.
            return SHADW_PROC_MIB_NONE;
        }

        return SHADW_PROC_MIB_NONE;
    }

    // KERN_PROCARGS2 is a direct CTL_KERN child: {CTL_KERN, KERN_PROCARGS2, pid}.
    if(name[1] == KERN_PROCARGS2 && namelen == 3) {
        if(name[2] == (int) getpid()) {
            return SHADW_PROC_MIB_ARGS2_SELF;
        }

        if(name[2] > 0) {
            return SHADW_PROC_MIB_ARGS2_OTHER;
        }
    }

    return SHADW_PROC_MIB_NONE;
}