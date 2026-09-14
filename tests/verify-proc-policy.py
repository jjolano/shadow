"""Exercise the real process-policy bodies with host doubles.

ProcessPolicy.m is compiled by no other check, yet it holds the process
classification caches, the pid-list compaction, the MIB classifier and the
boot-args answer. This gate splices the real bodies out of the source
(anchored so a reformat cannot break the pins), supplies host doubles for the
Darwin surface they call (struct kinfo_proc, proc_pidpath, sysctlnametomib,
the original sysctl, the isCPathRestricted: call), and runs them with
assertions.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "src/ShadowCore.dylib/policy/ProcessPolicy.m"
HEADER = ROOT / "src/ShadowCore.dylib/policy/ProcessPolicy.h"

source = POLICY.read_text()
header = HEADER.read_text()


def anchor_pattern(needle):
    """Regex for `needle`, tolerant of reformat spacing.

    These gates extract real bodies out of the hook sources and pin them. A
    clang-format pass must not be able to break that, so the pattern matches
    identifier/punctuation tokens separated by any whitespace, while the
    token sequence itself stays exact.
    """
    return r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )


def anchor(text, needle, start=0):
    """Index of `needle` in `text`, tolerant of reformat spacing."""
    match = re.search(anchor_pattern(needle), text[start:])
    if match is None:
        raise ValueError(f"anchor not found: {needle!r}")
    return start + match.start()


def pin(text, old, new):
    """Replace a pinned source snippet, tolerant of reformat spacing.

    Raises when the pin is gone, so a real rewrite still fails loudly."""
    match = re.search(anchor_pattern(old), text)
    if match is None:
        raise ValueError(f"pinned snippet not found: {old!r}")
    return text[:match.start()] + new + text[match.end():]


def pin_all(text, old, new):
    """Replace every occurrence of a pinned source snippet."""
    pattern = anchor_pattern(old)
    assert re.search(pattern, text), f"pinned snippet not found: {old!r}"
    return re.sub(pattern, lambda _: new, text)


def body(first, last):
    start = anchor(source, first)
    return source[start:anchor(source, last, start)]


def tail(first):
    start = anchor(source, first)
    return source[start:]


# The MIB kind enum and the original-call shape come from the header, so a
# change to either contract shows up here rather than silently drifting.
enum_end = anchor(header, "} shdw_proc_mib_kind_t;")
mib_enum = header[header.rindex("typedef enum {", 0, enum_end):enum_end + len("} shdw_proc_mib_kind_t;")]
fn_start = anchor(header, "typedef int (*shdw_sysctl_proc_fn)")
fn_end = anchor(header, "size_t newlen);", fn_start) + len("size_t newlen);")
sysctl_fn_typedef = header[fn_start:fn_end]


comm_table = body("static const char *const kRestrictedComm[]", "// Executable-path substring check")
path_token = body("static BOOL shdw_path_has_restricted_token", "// --- kinfo_proc classification cache")
proc_cache = body("#define SHADW_PROC_CACHE_SIZE 32", "BOOL shdw_proc_is_restricted(const struct kinfo_proc *p)")
proc_is_restricted = body("BOOL shdw_proc_is_restricted(const struct kinfo_proc *p)", "BOOL shdw_pid_restricted_uncached")
pid_uncached = body("BOOL shdw_pid_restricted_uncached", "// --- libproc pid classification cache")
pid_cache = body("#define SHADW_PID_CACHE_SIZE 32", "BOOL shdw_pid_is_restricted(pid_t pid)")
pid_is_restricted = body("BOOL shdw_pid_is_restricted(pid_t pid)", "int shdw_proc_pids_filtered")
pids_filtered = body("int shdw_proc_pids_filtered", "// --- filtered KERN_PROC list enumeration")
sanitize = body("void shdw_proc_sanitize_self_record", "// --- sysctl MIB classification")
bootargs_mib = body("static int shdw_bootargs_mib[2]", "shdw_proc_mib_kind_t shdw_proc_mib_kind")
mib_kind = body("shdw_proc_mib_kind_t shdw_proc_mib_kind", "// --- kern.bootargs answer")
bootargs = tail("int shdw_bootargs_filtered")

# One TTL for both classification caches is a contract (the two channels must
# not expose different staleness windows); the assertions below pin the
# value, so a drift fails with a named reason instead of a puzzling timeout.
assert re.search(r"#\s*define\s+SHADW_PROC_CACHE_TTL\s+2\b", proc_cache), "shared cache TTL changed"

# --- Objective-C surface -> host C ------------------------------------------
#
# The bodies are real: only the Foundation/Darwin calls they make are
# rewritten. NSString* stands in for the lowercased path C string on the
# host, the shared path classifier becomes a sentinel-prefix double, and
# time() is replaced by a controllable clock so the TTL boundary is
# observable.

lower_stmt = "NSString *lower = [@(path) lowercaseString];"
length_check = "if (!lower || [lower length] == 0)"
contains_token = "if ([lower containsString:@(kRestrictedComm[i])])"
cpath_call = "[_shadow isCPathRestricted:path]"
now_stmt = "time_t now = time(NULL);"

path_token = pin(path_token, length_check, "if (!lower || !lower[0])")
path_token = pin(path_token, contains_token, "if (test_contains(lower, kRestrictedComm[i]))")

proc_is_restricted = pin(proc_is_restricted, lower_stmt, "NSString *lower = test_lowercase(path);")
proc_is_restricted = pin_all(proc_is_restricted, cpath_call, "test_is_cpath_restricted(path)")
proc_is_restricted = pin(proc_is_restricted, now_stmt, "time_t now = test_time(NULL);")

pid_uncached = pin(pid_uncached, lower_stmt, "NSString *lower = test_lowercase(path);")
pid_uncached = pin_all(pid_uncached, cpath_call, "test_is_cpath_restricted(path)")

pid_is_restricted = pin(pid_is_restricted, lower_stmt, "NSString *lower = test_lowercase(path);")
pid_is_restricted = pin_all(pid_is_restricted, cpath_call, "test_is_cpath_restricted(path)")
pid_is_restricted = pin(pid_is_restricted, now_stmt, "time_t now = test_time(NULL);")


prefix_types = r'''
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

typedef bool BOOL;
#define YES true
#define NO false

typedef unsigned long NSUInteger;

// The extracted bodies hand NSString* a lowercased executable path; on the
// host that object pointer stands in for the C string.
typedef char NSString;

// Field-compatible subset of Darwin's struct kinfo_proc: exactly the members
// the policy bodies read. xnu's own layout is not needed to exercise them.
struct extern_proc_shadow {
    int p_flag;
    pid_t p_pid;
    char p_comm[17];            // MAXCOMLEN + 1
    struct timeval p_starttime; // __p_un.__p_starttime
};

struct eproc_shadow {
    pid_t e_ppid;
};

struct kinfo_proc {
    struct extern_proc_shadow kp_proc;
    struct eproc_shadow kp_eproc;
};

// Darwin <sys/sysctl.h> / <sys/proc.h> values (this host has no such SDK).
#define CTL_KERN 1
#define KERN_PROC 14
#define KERN_PROC_ALL 0
#define KERN_PROC_PID 1
#define KERN_PROC_PGRP 2
#define KERN_PROC_SESSION 3
#define KERN_PROC_TTY 4
#define KERN_PROC_UID 5
#define KERN_PROC_RUID 6
#define KERN_PROC_LCID 7
#define P_CONTROLT 0x00000002
#define P_SELECT 0x00000040
#define P_TRACED 0x00000800
#define P_EXEC 0x00004000
'''

prefix_doubles = r'''
// --- host doubles for the Darwin-only surface ------------------------------

static time_t test_now = 1000;
static time_t test_time(time_t *out) {
    if(out) {
        *out = test_now;
    }
    return test_now;
}

static char lower_buf[PATH_MAX];
static NSString* test_lowercase(const char* path) {
    size_t n = 0;
    for(; path[n] && n < sizeof(lower_buf) - 1; n++) {
        lower_buf[n] = (char)tolower((unsigned char)path[n]);
    }
    lower_buf[n] = '\0';
    return lower_buf;
}

static BOOL test_contains(const char* haystack, const char* needle) {
    return strstr(haystack, needle) != NULL;
}

// The shared path classifier (isCPathRestricted:): "/restricted" is this
// suite's sentinel prefix, the same convention the fd-path gate uses.
static BOOL test_is_cpath_restricted(const char* path) {
    return path && !strncmp(path, "/restricted", strlen("/restricted"));
}

// proc_pidpath double: a pid->path table over a fallback path. An unknown pid
// with no fallback is the sandbox-EPERM case the policy must fail open on.
#define PIDPATH_TABLE_SIZE 16
static struct {
    pid_t pid;
    const char* path;
} pidpath_table[PIDPATH_TABLE_SIZE];
static unsigned pidpath_table_count;
static const char* pidpath_default;
static unsigned pidpath_calls;
static pid_t pidpath_last_pid;

static void pidpath_set(pid_t pid, const char* path) {
    for(unsigned i = 0; i < pidpath_table_count; i++) {
        if(pidpath_table[i].pid == pid) {
            pidpath_table[i].path = path;
            return;
        }
    }
    assert(pidpath_table_count < PIDPATH_TABLE_SIZE);
    pidpath_table[pidpath_table_count].pid = pid;
    pidpath_table[pidpath_table_count].path = path;
    pidpath_table_count++;
}

static int proc_pidpath(int pid, void* buffer, uint32_t buffersize) {
    pidpath_calls++;
    pidpath_last_pid = pid;
    const char* path = NULL;
    for(unsigned i = 0; i < pidpath_table_count; i++) {
        if(pidpath_table[i].pid == pid) {
            path = pidpath_table[i].path;
            break;
        }
    }
    if(!path) {
        path = pidpath_default;
    }
    if(!path) {
        errno = EPERM;
        return 0;
    }
    size_t length = strlen(path);
    if(length + 1 > buffersize) {
        return 0;
    }
    memcpy(buffer, path, length + 1);
    return (int)(length + 1);
}

// sysctlnametomib double: the policy resolves one name and then classifies by
// the returned value, so the double controls both halves.
static int sysctlnametomib_ret;
static int sysctlnametomib_out[2] = {CTL_KERN, 99};
static unsigned sysctlnametomib_calls;
static const char* sysctlnametomib_last_name;

static int sysctlnametomib(const char* name, int* mibp, size_t* sizep) {
    sysctlnametomib_calls++;
    sysctlnametomib_last_name = name;
    if(sysctlnametomib_ret == 0 && *sizep >= 2) {
        mibp[0] = sysctlnametomib_out[0];
        mibp[1] = sysctlnametomib_out[1];
        *sizep = 2;
    }
    return sysctlnametomib_ret;
}

// original_sysctl double: serves the per-pid kinfo record the libproc
// fallback fetches, and can answer like the kernel's absent shape.
static struct kinfo_proc original_sysctl_record;
static int original_sysctl_ret = -1;
static BOOL original_sysctl_echo_pid = YES;
static unsigned original_sysctl_calls;

static int test_original_sysctl(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) {
    (void)newp;
    (void)newlen;
    original_sysctl_calls++;
    assert(namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID);
    if(original_sysctl_ret != 0) {
        return original_sysctl_ret;
    }
    original_sysctl_record.kp_proc.p_pid =
        original_sysctl_echo_pid ? (pid_t)name[3] : (pid_t)(name[3] + 1);
    if(!oldp) {
        *oldlenp = sizeof(original_sysctl_record);
        return 0;
    }
    memcpy(oldp, &original_sysctl_record, sizeof(original_sysctl_record));
    *oldlenp = sizeof(original_sysctl_record);
    return 0;
}

static shdw_sysctl_proc_fn original_sysctl;
'''


suffix = r'''
static void reset_host(void) {
    memset(shdw_proc_cache, 0, sizeof(shdw_proc_cache));
    shdw_proc_cache_next = 0;
    memset(shdw_pid_cache, 0, sizeof(shdw_pid_cache));
    shdw_pid_cache_next = 0;
    pidpath_table_count = 0;
    pidpath_default = NULL;
    pidpath_calls = 0;
    pidpath_last_pid = 0;
    memset(&original_sysctl_record, 0, sizeof(original_sysctl_record));
    original_sysctl_ret = -1;
    original_sysctl_echo_pid = YES;
    original_sysctl_calls = 0;
    original_sysctl = NULL;
    test_now = 1000;
}

int main(void) {
    // --- comm classification: folded substring, 16-char truncation ----------
    assert(!shdw_comm_is_restricted(NULL));
    assert(!shdw_comm_is_restricted(""));
    assert(shdw_comm_is_restricted("sshd"));
    assert(shdw_comm_is_restricted("SSHD"));
    assert(shdw_comm_is_restricted("ssh-keygen-SSHD"));
    assert(shdw_comm_is_restricted("CyDia"));
    assert(shdw_comm_is_restricted("Substrate"));
    assert(shdw_comm_is_restricted("launchdhook"));
    assert(!shdw_comm_is_restricted("ss"));
    assert(!shdw_comm_is_restricted("launchd"));
    // p_comm is a 16-char kernel field and the copy is capped to match: a
    // token ending at the cap matches, one cut off by it does not.
    assert(shdw_comm_is_restricted("0123456789absshd"));
    assert(!shdw_comm_is_restricted("0123456789abcsshd"));

    // --- executable-path token classifier -----------------------------------
    assert(!shdw_path_has_restricted_token(NULL));
    assert(!shdw_path_has_restricted_token(""));
    assert(shdw_path_has_restricted_token("/applications/cydia.app/cydia"));
    assert(shdw_path_has_restricted_token("/usr/libexec/dropbear"));
    assert(shdw_path_has_restricted_token("/usr/sbin/frida-server"));
    assert(shdw_path_has_restricted_token("/usr/libexec/amfid_payload"));
    assert(!shdw_path_has_restricted_token("/usr/bin/true"));
    assert(!shdw_path_has_restricted_token("/usr/libexec/launchd"));
    // Lowercase input is the caller's contract (every caller folds first);
    // the proc_pidpath cases below prove the fold happens.
    assert(!shdw_path_has_restricted_token("/Applications/Cydia.app/Cydia"));

    // --- uncached pid classification ----------------------------------------
    reset_host();
    pidpath_set(1234, "/usr/libexec/sshd");
    pidpath_set(1235, "/restricted/daemon");
    pidpath_set(1236, "/usr/bin/true");
    pidpath_set(1237, "/usr/libexec/SSHD");
    assert(!shdw_pid_restricted_uncached(0) && pidpath_calls == 0);
    assert(!shdw_pid_restricted_uncached(-1) && pidpath_calls == 0);
    assert(shdw_pid_restricted_uncached(1234) && pidpath_calls == 1);
    assert(shdw_pid_restricted_uncached(1235) && pidpath_calls == 2);
    assert(!shdw_pid_restricted_uncached(1236) && pidpath_calls == 3);
    assert(shdw_pid_restricted_uncached(1237) && pidpath_calls == 4);
    assert(!shdw_pid_restricted_uncached(9001) && pidpath_last_pid == 9001 && pidpath_calls == 5);
    // Un-cached by design: a repeat query re-classifies.
    assert(shdw_pid_restricted_uncached(1234) && pidpath_calls == 6);

    // --- kinfo classification cache (pid + start time, shared TTL) ----------
    reset_host();
    struct kinfo_proc kp;
    memset(&kp, 0, sizeof(kp));
    kp.kp_proc.p_pid = 2000;
    kp.kp_proc.p_starttime.tv_sec = 111;
    kp.kp_proc.p_starttime.tv_usec = 222;
    memcpy(kp.kp_proc.p_comm, "sample", 7);
    pidpath_set(2000, "/usr/bin/true");
    assert(!shdw_proc_is_restricted(&kp) && pidpath_calls == 1);
    // A cached verdict answers without a second libproc call, even after the
    // path changes underneath it.
    pidpath_set(2000, "/usr/libexec/sshd");
    assert(!shdw_proc_is_restricted(&kp) && pidpath_calls == 1);
    // The same pid with a different start time is a different key: pid reuse
    // cannot inherit a verdict.
    struct kinfo_proc reused = kp;
    reused.kp_proc.p_starttime.tv_sec = kp.kp_proc.p_starttime.tv_sec + 1;
    assert(shdw_proc_is_restricted(&reused) && pidpath_calls == 2);
    assert(!shdw_proc_is_restricted(&kp) && pidpath_calls == 2);
    // TTL boundary: one second inside the window still hits, the second one
    // (now - stamp == SHADW_PROC_CACHE_TTL) misses and re-classifies.
    test_now += SHADW_PROC_CACHE_TTL - 1;
    assert(!shdw_proc_is_restricted(&kp) && pidpath_calls == 2);
    test_now += 1;
    assert(shdw_proc_is_restricted(&kp) && pidpath_calls == 3);

    // p_comm decides before libproc is consulted — the root daemon whose
    // proc_pidpath EPERMs is still classified, and no call is wasted.
    reset_host();
    struct kinfo_proc daemon;
    memset(&daemon, 0, sizeof(daemon));
    daemon.kp_proc.p_pid = 2001;
    daemon.kp_proc.p_starttime.tv_sec = 1;
    memcpy(daemon.kp_proc.p_comm, "jailbreakd", 11);
    assert(shdw_proc_is_restricted(&daemon) && pidpath_calls == 0);
    // Clean comm + EPERM path = unclassifiable: kept (fail open).
    struct kinfo_proc unknown = daemon;
    unknown.kp_proc.p_pid = 2002;
    memcpy(unknown.kp_proc.p_comm, "sample", 7);
    assert(!shdw_proc_is_restricted(&unknown) && pidpath_calls == 1);
    // The path-token rule and then the shared classifier, each on a fresh key.
    reset_host();
    pidpath_set(2002, "/usr/sbin/frida-server");
    assert(shdw_proc_is_restricted(&unknown) && pidpath_calls == 1);
    reset_host();
    pidpath_set(2002, "/usr/bin/true");
    assert(!shdw_proc_is_restricted(&unknown) && pidpath_calls == 1);
    test_now += SHADW_PROC_CACHE_TTL;
    pidpath_set(2002, "/restricted/x");
    assert(shdw_proc_is_restricted(&unknown) && pidpath_calls == 2);

    // --- fixed-size round-robin eviction ------------------------------------
    reset_host();
    pidpath_set(3000, "/usr/libexec/sshd");
    pidpath_default = "/usr/bin/true";
    for(int i = 0; i < SHADW_PROC_CACHE_SIZE; i++) {
        struct kinfo_proc record;
        memset(&record, 0, sizeof(record));
        record.kp_proc.p_pid = (pid_t)(3000 + i);
        record.kp_proc.p_starttime.tv_sec = 5;
        (void)shdw_proc_is_restricted(&record);
    }
    assert(pidpath_calls == SHADW_PROC_CACHE_SIZE);
    struct kinfo_proc evicted;
    memset(&evicted, 0, sizeof(evicted));
    evicted.kp_proc.p_pid = 3000;
    evicted.kp_proc.p_starttime.tv_sec = 5;
    assert(shdw_proc_is_restricted(&evicted) && pidpath_calls == SHADW_PROC_CACHE_SIZE);
    // One more distinct pid rotates the first slot out.
    struct kinfo_proc fresh;
    memset(&fresh, 0, sizeof(fresh));
    fresh.kp_proc.p_pid = (pid_t)(3000 + SHADW_PROC_CACHE_SIZE);
    fresh.kp_proc.p_starttime.tv_sec = 5;
    assert(!shdw_proc_is_restricted(&fresh) && pidpath_calls == SHADW_PROC_CACHE_SIZE + 1);
    // Slot 0's key re-classifies; the untouched neighbours still hit.
    assert(shdw_proc_is_restricted(&evicted) && pidpath_calls == SHADW_PROC_CACHE_SIZE + 2);
    struct kinfo_proc neighbour = evicted;
    neighbour.kp_proc.p_pid = 3002;
    assert(!shdw_proc_is_restricted(&neighbour) && pidpath_calls == SHADW_PROC_CACHE_SIZE + 2);
    // ... and the key the re-classification just displaced does not.
    struct kinfo_proc displaced = evicted;
    displaced.kp_proc.p_pid = 3001;
    assert(!shdw_proc_is_restricted(&displaced) && pidpath_calls == SHADW_PROC_CACHE_SIZE + 3);

    // --- libproc pid cache (pid-only key, same TTL) --------------------------
    reset_host();
    pidpath_set(4001, "/usr/libexec/sshd");
    pidpath_set(4002, "/usr/bin/true");
    // The own pid is never restricted, and never classified at all.
    assert(!shdw_pid_is_restricted(getpid()) && pidpath_calls == 0);
    assert(shdw_pid_is_restricted(4001) && pidpath_calls == 1);
    assert(shdw_pid_is_restricted(4001) && pidpath_calls == 1);
    pidpath_set(4001, "/usr/bin/true");
    assert(shdw_pid_is_restricted(4001) && pidpath_calls == 1);
    test_now += SHADW_PROC_CACHE_TTL;
    assert(!shdw_pid_is_restricted(4001) && pidpath_calls == 2);

    // --- libproc fallback through the original sysctl ------------------------
    reset_host();
    original_sysctl_ret = 0;
    original_sysctl = test_original_sysctl;
    memcpy(original_sysctl_record.kp_proc.p_comm, "dropbear", 9);
    assert(shdw_pid_is_restricted(4100) && original_sysctl_calls == 1 && pidpath_calls == 1);
    // The fallback verdict is cached like any other.
    assert(shdw_pid_is_restricted(4100) && original_sysctl_calls == 1 && pidpath_calls == 1);
    // A record for a different pid is not ours to judge.
    reset_host();
    original_sysctl_ret = 0;
    original_sysctl = test_original_sysctl;
    original_sysctl_echo_pid = NO;
    assert(!shdw_pid_is_restricted(4101) && original_sysctl_calls == 1);
    // No record at all: fail open.
    reset_host();
    original_sysctl_ret = ENOENT;
    original_sysctl = test_original_sysctl;
    assert(!shdw_pid_is_restricted(4102) && original_sysctl_calls == 1);
    assert(!shdw_pid_is_restricted(4102) && original_sysctl_calls == 1 && pidpath_calls == 1);
    // No original call to fall back on: fail open too.
    reset_host();
    assert(!shdw_pid_is_restricted(4103) && pidpath_calls == 1);
    // The fail-open verdict stays cached for the TTL rather than re-probing
    // on every query.
    pidpath_set(4103, "/usr/libexec/sshd");
    assert(!shdw_pid_is_restricted(4103) && pidpath_calls == 1);
    test_now += SHADW_PROC_CACHE_TTL;
    assert(shdw_pid_is_restricted(4103) && pidpath_calls == 2);

    // --- in-place pid list compaction ---------------------------------------
    reset_host();
    pidpath_set(5001, "/usr/libexec/sshd");
    pidpath_set(5002, "/usr/bin/true");
    pidpath_set(5003, "/restricted/daemon");
    pidpath_set(5004, "/usr/bin/ls");
    pidpath_set(getpid(), "/usr/libexec/sshd");
    pid_t pids[5] = {5001, 5002, 5003, 5004, getpid()};
    int kept = shdw_proc_pids_filtered(pids, 5);
    assert(kept == 3);
    assert(pids[0] == 5002 && pids[1] == 5004 && pids[2] == getpid());
    // Everything removed answers zero (the caller reads that as "none").
    reset_host();
    pidpath_set(5001, "/usr/libexec/sshd");
    pidpath_set(5003, "/restricted/daemon");
    pid_t only[2] = {5001, 5003};
    assert(shdw_proc_pids_filtered(only, 2) == 0);
    assert(shdw_proc_pids_filtered(only, 2) == 0);
    assert(shdw_proc_pids_filtered(only, 0) == 0);

    // --- self-record sanitization -------------------------------------------
    struct kinfo_proc self;
    memset(&self, 0, sizeof(self));
    self.kp_proc.p_flag = P_TRACED | P_SELECT | P_CONTROLT;
    self.kp_eproc.e_ppid = 4242;
    shdw_proc_sanitize_self_record(&self);
    assert((self.kp_proc.p_flag & P_TRACED) == 0);
    assert((self.kp_proc.p_flag & P_SELECT) == 0);
    assert(self.kp_proc.p_flag == P_CONTROLT);
    assert(self.kp_eproc.e_ppid == 1);
    memset(&self, 0, sizeof(self));
    self.kp_proc.p_flag = P_EXEC;
    self.kp_eproc.e_ppid = 7;
    shdw_proc_sanitize_self_record(&self);
    assert(self.kp_proc.p_flag == P_EXEC);
    assert(self.kp_eproc.e_ppid == 1);

    // --- MIB classification --------------------------------------------------
    // The boot-args MIB is resolved once, on the first CTL_KERN query, under
    // its real name; everything else is classified by value.
    shdw_bootargs_mib_resolved = NO;
    shdw_bootargs_mib[0] = 0;
    shdw_bootargs_mib[1] = 0;
    sysctlnametomib_ret = 0;
    sysctlnametomib_out[0] = CTL_KERN;
    sysctlnametomib_out[1] = 99;
    int outside[3] = {2, KERN_PROC, KERN_PROC_ALL};
    assert(shdw_proc_mib_kind(outside, 3) == SHADW_PROC_MIB_NONE && sysctlnametomib_calls == 0);
    int list3[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    assert(shdw_proc_mib_kind(list3, 3) == SHADW_PROC_MIB_LIST);
    assert(sysctlnametomib_calls == 1 && !strcmp(sysctlnametomib_last_name, "kern.bootargs"));
    assert(shdw_bootargs_mib[0] == CTL_KERN && shdw_bootargs_mib[1] == 99);
    int bootargs2[2] = {CTL_KERN, 99};
    assert(shdw_proc_mib_kind(bootargs2, 2) == SHADW_PROC_MIB_BOOTARGS);
    assert(sysctlnametomib_calls == 1);

    assert(shdw_proc_mib_kind(NULL, 0) == SHADW_PROC_MIB_NONE);
    assert(shdw_proc_mib_kind(NULL, 3) == SHADW_PROC_MIB_NONE);
    int list4[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    assert(shdw_proc_mib_kind(list4, 4) == SHADW_PROC_MIB_LIST);
    int list4bad[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 1};
    assert(shdw_proc_mib_kind(list4bad, 4) == SHADW_PROC_MIB_NONE);
    int list2[2] = {CTL_KERN, KERN_PROC};
    assert(shdw_proc_mib_kind(list2, 2) == SHADW_PROC_MIB_NONE);
    const int selectors[] = {KERN_PROC_PGRP, KERN_PROC_TTY, KERN_PROC_UID, KERN_PROC_RUID};
    for(unsigned s = 0; s < sizeof(selectors) / sizeof(selectors[0]); s++) {
        int list[4] = {CTL_KERN, KERN_PROC, selectors[s], 42};
        assert(shdw_proc_mib_kind(list, 4) == SHADW_PROC_MIB_LIST);
        assert(shdw_proc_mib_kind(list, 3) == SHADW_PROC_MIB_NONE);
    }
    // SESSION is a list selector too, but the kernel answers ENOTSUP for it,
    // so it is deliberately absent from the supported set; LCID likewise.
    int session[4] = {CTL_KERN, KERN_PROC, KERN_PROC_SESSION, 1};
    assert(shdw_proc_mib_kind(session, 4) == SHADW_PROC_MIB_NONE);
    int lcid[4] = {CTL_KERN, KERN_PROC, KERN_PROC_LCID, 1};
    assert(shdw_proc_mib_kind(lcid, 4) == SHADW_PROC_MIB_NONE);
    // Per-pid selectors: self, other, and the non-positive shapes.
    int pid_self[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid()};
    assert(shdw_proc_mib_kind(pid_self, 4) == SHADW_PROC_MIB_PID_SELF);
    int pid_other[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, 4242};
    assert(shdw_proc_mib_kind(pid_other, 4) == SHADW_PROC_MIB_PID_OTHER);
    int pid_zero[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, 0};
    assert(shdw_proc_mib_kind(pid_zero, 4) == SHADW_PROC_MIB_NONE);
    int pid_negative[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, -1};
    assert(shdw_proc_mib_kind(pid_negative, 4) == SHADW_PROC_MIB_NONE);
    int pid3[3] = {CTL_KERN, KERN_PROC, KERN_PROC_PID};
    assert(shdw_proc_mib_kind(pid3, 3) == SHADW_PROC_MIB_NONE);
    // The legacy argv/env channel and its 2 sibling share this classifier.
    int args_self[3] = {CTL_KERN, 38, (int)getpid()};
    assert(shdw_proc_mib_kind(args_self, 3) == SHADW_PROC_MIB_ARGS_SELF);
    int args_other[3] = {CTL_KERN, 38, 4242};
    assert(shdw_proc_mib_kind(args_other, 3) == SHADW_PROC_MIB_ARGS_OTHER);
    int args2_self[3] = {CTL_KERN, 49, (int)getpid()};
    assert(shdw_proc_mib_kind(args2_self, 3) == SHADW_PROC_MIB_ARGS2_SELF);
    int args2_other[3] = {CTL_KERN, 49, 4242};
    assert(shdw_proc_mib_kind(args2_other, 3) == SHADW_PROC_MIB_ARGS2_OTHER);
    int args_zero[3] = {CTL_KERN, 49, 0};
    assert(shdw_proc_mib_kind(args_zero, 3) == SHADW_PROC_MIB_NONE);
    int args4[4] = {CTL_KERN, 49, (int)getpid(), 0};
    assert(shdw_proc_mib_kind(args4, 4) == SHADW_PROC_MIB_NONE);
    // An unresolvable boot-args MIB classifies NONE: pass-through untouched.
    shdw_bootargs_mib_resolved = NO;
    shdw_bootargs_mib[0] = 0;
    shdw_bootargs_mib[1] = 0;
    sysctlnametomib_ret = ENOENT;
    assert(shdw_proc_mib_kind(bootargs2, 2) == SHADW_PROC_MIB_NONE);
    int kern1[1] = {CTL_KERN};
    assert(shdw_proc_mib_kind(kern1, 1) == SHADW_PROC_MIB_NONE);
    assert(sysctlnametomib_calls == 2);

    // --- kern.bootargs answer ------------------------------------------------
    size_t len;
    char buf[8];
    errno = 0;
    assert(shdw_bootargs_filtered(NULL, NULL) == -1 && errno == EFAULT);
    errno = 0;
    len = 64;
    assert(shdw_bootargs_filtered(NULL, &len) == 0 && len == 1 && errno == 0);
    len = 0;
    errno = 0;
    assert(shdw_bootargs_filtered(buf, &len) == -1 && errno == ENOMEM && len == 1);
    len = 1;
    errno = 0;
    assert(shdw_bootargs_filtered(buf, &len) == 0 && len == 1 && buf[0] == '\0');
    memset(buf, 'x', sizeof(buf));
    len = sizeof(buf);
    errno = 0;
    assert(shdw_bootargs_filtered(buf, &len) == 0 && len == 1 && buf[0] == '\0' && buf[1] == 'x');

    puts("verify-proc-policy: all assertions passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-proc-policy-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    test.write_text(
        prefix_types
        + mib_enum
        + sysctl_fn_typedef
        + prefix_doubles
        + comm_table
        + path_token
        + proc_cache
        + proc_is_restricted
        + pid_uncached
        + pid_cache
        + pid_is_restricted
        + pids_filtered
        + sanitize
        + bootargs_mib
        + mib_kind
        + bootargs
        + suffix
    )
    subprocess.run([
        os.environ.get("CC", "cc"), "-D_GNU_SOURCE", "-std=c11", "-Wall", "-Wextra",
        "-pthread", str(test), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
