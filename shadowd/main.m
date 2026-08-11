//
//  main.m
//  shadowd
//
//  Root LaunchDaemon owning ALL kernel read/write (krw) for vnode-layer
//  file hiding on behalf of the Shadow tweak.
//
//  Architecture (fixed by design review — implement exactly):
//    1. KRW init.  Daemon is root — no getuid spoofing, no client-side krw.
//       - Dopamine (rootless arm64e): dlopen /var/jb/basebin/libjailbreak.dylib,
//         dlsym jbdInitPPLRW + kread*/kwrite* + kreadbuf/kwritebuf + kread_ptr +
//         kwrite_ptr + proc_find + proc_rele.  STATUS-RETURNING buffer
//         primitives (kreadbuf/kwritebuf) are used for all reads/writes;
//         every krw call checks its return status.
//       - palera1n/legacy (tfp0, arm64 A8-A11 only): task_for_pid(0) +
//         mach_vm_read_overwrite/mach_vm_write wrappers + pfinder allproc
//         scan.  NEVER tfp0 on arm64e (PAC makes the allproc walk unsafe
//         without PPL primitives).  arm64e without libjailbreak → disabled.
//       - Retry jbdInitPPLRW every 2s up to 30s (daemon may start before
//         jailbreakd is ready).  Any failure → logged, feature disabled for
//         this run, daemon stays alive but idles.  NEVER crash.
//    2. Hard version gate: iOS 15.0–16.6.1 ONLY.
//    3. Hide/release with RETAINED fds — the open fd IS the kernel-managed
//       vnode reference; no manual v_usecount/v_iocount edits.
//    4. Multi-owner lease model: owners are (pid, proc start time) derived
//       from the mach audit trailer; the client reply port is the lease with
//       a dead-name notification; kill(pid,0)+start-time polling fallback.
//    5. Write-ahead ledger (mayBeHidden semantics), bootUUID keyed,
//       PATH-BASED recovery — never write through a stale vnode blindly.
//    6. Mach IPC server (synchronous) on MACH_SERVICE_NAME.  No paths and no
//       pids in the protocol — the daemon derives everything from its own
//       fixed compiled allowlist and the audit trailer.
//    7. SIGTERM/SIGINT: clear all VISSHADOW flags (fds held), verify clears,
//       close fds, durably remove ledger, exit.
//
//  Kernel-touching code is copied verbatim from the reviewed on-disk
//  references:
//    vnb-xfdxh/vnode/kernel.m    (Dopamine-era: PAC unsign, t1sz, jbdInitPPLRW,
//                                 offsets)
//    vnb-plus007/main.m          (tfp0 init, kread/kwrite wrappers, pfinder
//                                 allproc scan, get_kbase)
//    vnb-plus007/offsets.m       (per-version proc offsets)
//    jelbrekLib/offsetof.c       (vnode v_type/v_id/v_flags offsets)
//
//  The OLD in-process implementation (Shadow.dylib/hooks/vnode.x) was
//  rejected in review and its design is NOT reused here.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <mach/bootstrap.h>
#import <mach/message.h>
#import <mach/notify.h>
#import <mach/vm_page_size.h>
#import <mach/vm_region.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/time.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <inttypes.h>
#import <signal.h>
#import <stdatomic.h>

#include "../common.h"   // BUNDLE_ID, MACH_SERVICE_NAME, SHADOW_PREFS_PLIST
#include "../protocol.h" // SHADOWD_MAGIC/VERSION, ops, request/reply structs
#include "krw.h"         // kernel r/w backends + vnode ops (shadowd/krw.m)
#include "ledger.h"      // write-ahead ledger + record format/parse (shadowd/ledger.m)

// SDK 16.5's mach/bootstrap.h is a compatibility stub — declare the classic
// prototype directly (name_t decays to const char *).
extern kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service_name, mach_port_t *service_port);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Status codes (errno values): 0 ok | EPERM | ENOTSUP | EBUSY
#define SHADOWD_STATUS_OK      0
#define SHADOWD_STATUS_EPERM   EPERM
#define SHADOWD_STATUS_ENOTSUP ENOTSUP
#define SHADOWD_STATUS_EBUSY   EBUSY

// Fixed compiled allowlist.  NOTE (review finding): Shadow.dylib itself,
// shadowd, its plist and the ledger are deliberately NOT hidden — hiding the
// recovery dylib creates a respring deadlock; dyld-level filtering already
// covers the dylib name.
//
// KNOWN RESIDUAL (raw syscall probes): VISSHADOW is a kernel-global vnode
// flag — there is no per-process visibility. Extending this list to
// jailbreak indicator paths (/var/jb, /var/lib/dpkg, libhooker/libellekit,
// /etc/apt, TrollStore markers) would hide them from EVERY process,
// breaking the jailbreak itself (dpkg, Sileo/Zebra, launchd spawning,
// tweak dlopen, and shadowd's own runtime — its log lives under /var/jb and
// krw init dlopens /var/jb/basebin/libjailbreak.dylib). Per-process
// concealment is userspace-only (isCallerExternal gating in the hooks),
// which inline `svc #0x80` open/stat/access probes bypass; closing that gap
// needs per-process kernel machinery (namei/proc-aware hiding) that XNU does
// not expose. Accepted residual as of v5: no mainstream detector uses raw
// syscalls (IOSSecuritySuite/DTTjailbreakDetection do not; the only users are
// cloudphone-style anti-fraud kits and KSCrash crash metadata, which is not
// anti-cheat). The userspace libc-vs-syscall mismatch this creates is the
// standard tradeoff of every userspace-only bypass (Liberty-class).
static NSString *const kAllowlist[] = {
    @(SHADOW_PREFS_PLIST),                                          // /var/mobile/... (rootful AND rootless)
    @"/var/jb/var/mobile/Library/Preferences/" BUNDLE_ID ".plist",  // rootless-prefixed variant
    @"/Library/PreferenceBundles/ShadowSettings.bundle",            // rootful
    @"/var/jb/Library/PreferenceBundles/ShadowSettings.bundle",     // rootless
};
static const NSUInteger kAllowlistCount = sizeof(kAllowlist) / sizeof(kAllowlist[0]);

#define POLL_INTERVAL      10   // seconds, owner-death fallback + release retry
#define SHUTDOWN_MAX_ATTEMPTS 30   // 30 * 2s of retries before exiting non-zero

// ---------------------------------------------------------------------------
// Logging (daemon needs REAL logging — NSLog is compiled out by common.h in
// release builds, so everything goes through fprintf to stderr + a log file)
// ---------------------------------------------------------------------------

static FILE *gLogFile = NULL;

static NSString *log_path(void) {
    static NSString *path = nil;
    if (!path) {
        // Rootless: /var/jb/var/log/shadowd.log (spec); rootful: /var/log/...
        path = (access("/var/jb", F_OK) == 0)
            ? @"/var/jb/var/log/shadowd.log"
            : @"/var/log/shadowd.log";
    }
    return path;
}

void shdw_log(const char *fmt, ...) {
    va_list ap;
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm);

    va_start(ap, fmt);
    fprintf(stderr, "[shadowd %s] ", stamp);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    if (!gLogFile) {
        gLogFile = fopen(log_path().UTF8String, "a");
        if (gLogFile) setvbuf(gLogFile, NULL, _IOLBF, 0);
    }
    if (gLogFile) {
        va_start(ap, fmt);
        fprintf(gLogFile, "[%s] ", stamp);
        vfprintf(gLogFile, fmt, ap);
        fprintf(gLogFile, "\n");
        va_end(ap);
        fflush(gLogFile);
    }
}

// ---------------------------------------------------------------------------
// Rootless detection (spec: check for /var/jb existence)
// ---------------------------------------------------------------------------

bool gIsRootless = false;

// ---------------------------------------------------------------------------
// Version gate (hard ceiling: iOS 15.0–16.6.1 ONLY)
// ---------------------------------------------------------------------------

// Parse "Darwin Kernel Version 22.6.0: ..." from kern.version.  The result is
// cached in gDarwinMajor/gDarwinMinor — offset_init dispatches off the Darwin
// major (A1), and version_gate FAILS CLOSED when it is unavailable (A4).
int gDarwinMajor = 0;
int gDarwinMinor = 0;

static bool darwin_version(void) {
    char kern_version[512] = {};
    size_t size = sizeof(kern_version);
    if (sysctlbyname("kern.version", &kern_version, &size, NULL, 0) != 0) {
        return false;
    }
    return sscanf(kern_version, "Darwin Kernel Version %d.%d", &gDarwinMajor, &gDarwinMinor) == 2;
}

// Hard ceiling gate: iOS 15.0–16.6.1 ONLY.  FAIL CLOSED: if Darwin/version
// information is unavailable, the feature is DISABLED — no CF-only fallback
// (A4).  Darwin 21 = iOS 15 (entire line supported); Darwin 22 = iOS 16, and
// because Darwin 22.6 also covers 16.7.x, the exact ceiling is bound via
// kern.osproductversion (≤ 16.6.1).
static bool version_gate(void) {
    double cf = kCFCoreFoundationVersionNumber;

    shdw_log("kCFCoreFoundationVersionNumber: %.3f", cf);
    if (!darwin_version()) {
        shdw_log("UNSUPPORTED: kern.version unavailable — FAIL CLOSED, feature disabled");
        return false;
    }
    shdw_log("Darwin %d.%d", gDarwinMajor, gDarwinMinor);

    if (cf < kCFCoreFoundationVersionNumber_iOS_15_0) {
        shdw_log("UNSUPPORTED: iOS < 15.0 (CF %.3f) — feature disabled", cf);
        return false;
    }
    if (cf >= kCFCoreFoundationVersionNumber_iOS_17_0) {
        shdw_log("UNSUPPORTED: iOS >= 17.0 (CF %.3f) — feature disabled", cf);
        return false;
    }

    if (gDarwinMajor == 21) {
        // iOS 15.x — the whole line is inside the supported range.
        shdw_log("version gate: supported (Darwin 21 = iOS 15.x)");
        return true;
    }
    if (gDarwinMajor == 22) {
        // iOS 16.x — must bound to 16.6.1 (Darwin 22.6 also covers 16.7.x).
        char pv[64] = {0};
        size_t pvsz = sizeof(pv);
        if (sysctlbyname("kern.osproductversion", pv, &pvsz, NULL, 0) != 0 || pv[0] == '\0') {
            shdw_log("UNSUPPORTED: Darwin 22 but kern.osproductversion unavailable — FAIL CLOSED");
            return false;
        }
        int maj = 0, min = 0, pat = 0;
        int n = sscanf(pv, "%d.%d.%d", &maj, &min, &pat);
        if (n < 2 || maj != 16 || min > 6 || (min == 6 && n >= 3 && pat > 1)) {
            shdw_log("UNSUPPORTED: iOS %s (need <= 16.6.1) — feature disabled", pv);
            return false;
        }
        shdw_log("version gate: supported (Darwin 22 = iOS %s)", pv);
        return true;
    }

    shdw_log("UNSUPPORTED: Darwin %d.%d — feature disabled", gDarwinMajor, gDarwinMinor);
    return false;
}

// ---------------------------------------------------------------------------
// Owner identity + resource map
// ---------------------------------------------------------------------------

// Owner key: "pid-sec-usec" (kernel-derived pid + proc start time, survives
// PID reuse).
static NSString *owner_key(pid_t pid, uint64_t sec, uint64_t usec) {
    return [NSString stringWithFormat:@"%d-%llu-%llu", pid, sec, usec];
}

static void parse_owner_key(NSString *key, pid_t *pid, uint64_t *sec, uint64_t *usec) {
    *pid = 0; *sec = 0; *usec = 0;
    NSArray<NSString *> *parts = [key componentsSeparatedByString:@"-"];
    if (parts.count != 3) return;
    *pid = (pid_t)[parts[0] intValue];
    *sec = (uint64_t)[parts[1] longLongValue];
    *usec = (uint64_t)[parts[2] longLongValue];
}

// Process start time via sysctl KERN_PROC_PID (libproc.h is not in the
// public SDK; kinfo_proc is).  kp_proc.p_starttime = timeval.
static bool owner_start_time(pid_t pid, uint64_t *sec, uint64_t *usec) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    memset(&kp, 0, sizeof(kp));
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0) {
        return false;
    }
    if (len == 0) return false;
    *sec = (uint64_t)kp.kp_proc.p_starttime.tv_sec;
    *usec = (uint64_t)kp.kp_proc.p_starttime.tv_usec;
    return true;
}

// ShadowResource's @interface + gResources extern live in recovery.h (shared
// with the test harness); this file only holds the @implementation + the
// gResources definition.
#import "recovery.h"

@implementation ShadowResource

+ (instancetype)resourceWithFd:(int)fd vnode:(uint64_t)vnode vId:(uint64_t)vId
                       flagSet:(BOOL)flagSet verified:(BOOL)verified owner:(NSString *)ownerKey {
    ShadowResource *nr = [ShadowResource new];
    nr.fd = fd;
    nr.vnode = vnode;
    nr.vId = vId;
    nr.flagSet = flagSet;
    nr.verified = verified;
    nr.owners = [NSMutableSet setWithObject:ownerKey];
    return nr;
}

@end

// All resource/ledger/kernel activity: ONE serial queue (spec: single serial
// daemon writer).
static dispatch_queue_t gKernelQueue;
static dispatch_queue_t gServerQueue;   // mach server queue (created in setup_ipc_server)

NSMutableDictionary<NSString *, ShadowResource *> *gResources;
static NSMutableSet<NSString *> *gPendingReleases;   // release retries

// Lease bookkeeping (declared here so owner_gone can clean up; populated in
// setup_ipc_server): reply port → owner key, and owner key → live port count
// (A17: an owner is gone only when ALL of its reply ports are dead).
static NSMutableDictionary<NSNumber *, NSString *> *gLeases;
static NSMutableDictionary<NSString *, NSNumber *> *gOwnerPortCounts;

static void owner_gone(NSString *ownerKey);

// Drop every lease/port-count entry belonging to an owner (dead-name or
// polling detected death).  Deallocation of the port names is owned by the
// dead-name notification handler (it deallocs on EVERY path, including the
// unknown-port case, and the armed notification always fires when the port
// dies) — deallocating here would race in-flight notifications and could
// hit a recycled name.
static void drop_owner_leases(NSString *ownerKey) {
    NSMutableArray<NSNumber *> *deadPorts = [NSMutableArray array];
    for (NSNumber *port in [gLeases allKeys]) {
        if ([gLeases[port] isEqualToString:ownerKey]) {
            [deadPorts addObject:port];
        }
    }
    for (NSNumber *port in deadPorts) {
        [gLeases removeObjectForKey:port];
    }
    [gOwnerPortCounts removeObjectForKey:ownerKey];
}

// A8: restart-adopted resources (fd == -1) are READ-ONLY — the saved vnode
// address may be reclaimed between any check and write (TOCTOU), so VISSHADOW
// is NEVER written through it.  Clearing an adopted resource goes through a
// FRESH open: if it opens, it's visible — re-resolve from the fresh fd and
// clear if flagged; if ENOENT, leave it hidden (mark degraded), and retry
// later — a kernel reboot/reclaim clears it naturally.
static bool adopted_clear(ShadowResource *res, NSString *path) {
    int fd2 = open(path.UTF8String, O_RDONLY);
    if (fd2 < 0) {
        if (errno == ENOENT) {
            shdw_log("adopted_clear %s: still hidden (ENOENT) — degraded, retrying later", path.UTF8String);
        } else {
            shdw_log("adopted_clear %s: open failed (%s) — retrying later", path.UTF8String, strerror(errno));
        }
        return false;
    }
    uint64_t vnode = 0, vId = 0;
    if (!resolve_vnode_for_fd(fd2, &vnode, &vId)) {
        shdw_log("adopted_clear %s: re-resolve failed", path.UTF8String);
        close(fd2);
        return false;
    }
    uint32_t flags = 0;
    bool flagged = krw_read32(vnode + OFF_VNODE_V_FLAGS, &flags) && (flags & VISSHADOW) != 0;
    if (flagged) {
        if (vnode_set_flag(vnode, false) != VFLAG_OK) {
            shdw_log("adopted_clear %s: clear unverified — retaining", path.UTF8String);
            close(fd2);
            return false;
        }
    }
    close(fd2);
    return true;
}

// Teardown a resource: clear VISSHADOW (fd held), verify, THEN durably remove
// the ledger record (A6: teardown does NOT complete — fd + resource are kept —
// if the durable removal failed), then close the fd.  Returns false when the
// caller must retain fd + record and retry later.
static bool resource_teardown(ShadowResource *res, NSString *path) {
    if (res.fd < 0) {
        // Restart-adopted: read-only saved vnode — fresh-open path only (A8).
        if (!adopted_clear(res, path)) {
            return false;
        }
        res.flagSet = NO;
        if (!ledger_remove_path_records(path.UTF8String)) {
            shdw_log("teardown %s: ledger removal failed — keeping resource", path.UTF8String);
            return false;
        }
        [gResources removeObjectForKey:path];
        shdw_log("released: %s", path.UTF8String);
        return true;
    }

    if (res.flagSet) {
        if (vnode_set_flag(res.vnode, false) != VFLAG_OK) {
            shdw_log("teardown %s: clear VISSHADOW unverified — retaining fd + record", path.UTF8String);
            return false;
        }
        res.flagSet = NO;
    }
    // A6/NEW-1: durable record removal BEFORE closing — if it fails, keep the
    // fd and the resource; verified must NOT stay YES (a resource is only
    // fully released when BOTH the flag clear AND the ledger removal are
    // durable), so a later acquire cannot treat it as a verified hidden
    // resource while the record is still pending removal.
    if (!ledger_remove_path_records(path.UTF8String)) {
        shdw_log("teardown %s: ledger removal failed — keeping fd + resource (verified cleared)", path.UTF8String);
        res.verified = NO;
        return false;
    }
    close(res.fd);
    res.fd = -1;
    [gResources removeObjectForKey:path];
    shdw_log("released: %s", path.UTF8String);
    return true;
}

// Remove one owner everywhere; tear down resources with no owners left.
// gLeases/gOwnerPortCounts are only ever touched on the SERVER queue
// (install_lease, dead-name handler), so the lease cleanup is dispatched
// there — owner_gone itself runs on the kernel queue.
static void owner_gone(NSString *ownerKey) {
    if (gServerQueue) {
        dispatch_async(gServerQueue, ^{
            drop_owner_leases(ownerKey);
        });
    }
    for (NSString *path in [gResources allKeys]) {
        ShadowResource *res = gResources[path];
        if (![res.owners containsObject:ownerKey]) continue;
        [res.owners removeObject:ownerKey];
        shdw_log("owner %s gone — releasing %s", ownerKey.UTF8String, path.UTF8String);
        if (res.owners.count == 0 && res.flagSet) {
            if (!resource_teardown(res, path)) {
                [gPendingReleases addObject:path];
            }
        }
    }
}

// Owner-death check: kill(pid, 0) + start-time comparison (survives PID reuse).
static bool owner_dead(NSString *ownerKey) {
    pid_t pid; uint64_t sec, usec;
    parse_owner_key(ownerKey, &pid, &sec, &usec);
    if (pid <= 0) return true;
    bool alive = (kill(pid, 0) == 0) || (errno != ESRCH);
    if (alive && (sec != 0 || usec != 0)) {
        uint64_t cs = 0, cu = 0;
        if (!owner_start_time(pid, &cs, &cu)) {
            alive = false;
        } else if (cs != sec || cu != usec) {
            shdw_log("sweep: pid %d reused (start time mismatch)", pid);
            alive = false;
        }
    }
    return !alive;
}

// Polling fallback owner-death detection + repair pass for unverified hides
// (A5: a hide whose write outcome was unknown is re-attempted until verified)
// + pending release retries.
static void sweep_owners(void) {
    NSMutableSet<NSString *> *deadOwners = [NSMutableSet set];
    for (NSString *path in [gResources allKeys]) {
        ShadowResource *res = gResources[path];
        for (NSString *ownerKey in res.owners) {
            if (owner_dead(ownerKey)) {
                shdw_log("sweep: owner %s dead", ownerKey.UTF8String);
                [deadOwners addObject:ownerKey];
            }
        }
        // Repair pass: an unverified hide may actually be visible — re-attempt
        // the set until it verifies (or the resource is torn down).
        if (res.flagSet && !res.verified) {
            vflag_result_t r = vnode_set_flag(res.vnode, true);
            if (r == VFLAG_OK) {
                res.verified = YES;
                for (NSString *k in res.owners) {
                    ledger_update_record(path.UTF8String, k.UTF8String, res.vnode, res.vId, 1 /*hidden*/);
                }
                shdw_log("sweep: verified hide for %s", path.UTF8String);
            }
        }
    }
    for (NSString *k in deadOwners) {
        owner_gone(k);
    }
    // NEW-1: a resource whose flag clear VERIFIED but whose durable ledger
    // removal failed stays in the retry set even with flagSet == NO — only an
    // owner (re-acquire) or a completed teardown removes it from the set.
    for (NSString *path in [gPendingReleases copy]) {
        ShadowResource *res = gResources[path];
        if (!res || res.owners.count > 0) {
            [gPendingReleases removeObject:path];
            continue;
        }
        if (resource_teardown(res, path)) {
            [gPendingReleases removeObject:path];
        }
    }
}

// ---------------------------------------------------------------------------
// Acquire / release (on the kernel queue)
// ---------------------------------------------------------------------------

bool allowlisted(const char *path) {
    for (NSUInteger i = 0; i < kAllowlistCount; i++) {
        if (strcmp(kAllowlist[i].UTF8String, path) == 0) return true;
    }
    return false;
}

// A22: requests arriving while krw init is still running return EBUSY
// IMMEDIATELY — no long wait.  The client times out after ~2s and destroys
// its reply port; hiding on its behalf with no lease must not happen.  A
// permanently disabled krw backend answers ENOTSUP.
static uint32_t acquire_status_if_ready(void) {
    krw_state_t st = atomic_load(&gKrwState);
    if (st == KRW_INIT) {
        return SHADOWD_STATUS_EBUSY;
    }
    if (st != KRW_READY) {
        return SHADOWD_STATUS_ENOTSUP;
    }
    return SHADOWD_STATUS_OK;
}

// A21(a): roll back ONLY what this acquire call did — resources it created
// (their only owner is this ownerKey) are torn down; pre-existing resources
// the call joined are un-joined and their per-owner WAL record removed
// (A21(b)).  Pre-existing ownership of OTHER owners is never touched.
static void rollback_acquire(NSString *ownerKey, NSArray<NSString *> *created, NSArray<NSString *> *joined) {
    for (NSString *path in created) {
        ShadowResource *res = gResources[path];
        if (!res) continue;
        [res.owners removeObject:ownerKey];
        if (!resource_teardown(res, path)) {
            [gPendingReleases addObject:path];
        }
    }
    for (NSString *path in joined) {
        ShadowResource *res = gResources[path];
        if (!res || ![res.owners containsObject:ownerKey]) continue;
        [res.owners removeObject:ownerKey];
        ledger_remove_owner_record(path.UTF8String, ownerKey.UTF8String);
        if (res.owners.count == 0 && res.flagSet) {
            if (!resource_teardown(res, path)) {
                [gPendingReleases addObject:path];
            }
        }
    }
}

// A3: join-existing branch of acquire (extracted verbatim).  Returns the
// per-path status: EBUSY when the hide could not be re-verified or the WAL
// write failed, OK otherwise (including the already-an-owner case).
static uint32_t acquire_join_existing(ShadowResource *res, NSString *path, NSString *ownerKey, NSMutableArray<NSString *> *joined) {
    // A5: an acquire must NOT succeed for a resource whose VISSHADOW
    // state is unverified.  Re-attempt the set; unless it verifies,
    // no owner is added and the acquire fails for this resource.
    if (!res.verified) {
        if (vnode_set_flag(res.vnode, true) == VFLAG_OK) {
            res.verified = YES;
            res.flagSet = YES;   // re-hide restored the flag: teardown gates key on flagSet
            shdw_log("acquire %s: hide re-verified", path.UTF8String);
        } else {
            shdw_log("acquire %s: hide still UNVERIFIED — EBUSY", path.UTF8String);
            return SHADOWD_STATUS_EBUSY;
        }
    }
    if (![res.owners containsObject:ownerKey]) {
        // A16: the WAL write is part of the acquire — fail it if the
        // durable per-owner record cannot be written.
        if (!ledger_add_record(path.UTF8String, ownerKey.UTF8String, res.vnode, res.vId, 1 /*hidden*/)) {
            shdw_log("acquire %s: ledger write failed (dedup)", path.UTF8String);
            return SHADOWD_STATUS_EBUSY;
        }
        [res.owners addObject:ownerKey];
        [joined addObject:path];
        shdw_log("acquire %s: added owner %s", path.UTF8String, ownerKey.UTF8String);
    }
    return SHADOWD_STATUS_OK;
}

// A3: create-new branch of acquire (extracted verbatim).  Returns the
// per-path status; the ENOENT/ENOTDIR skip counts as OK.
static uint32_t acquire_create_new(NSString *path, NSString *ownerKey, NSMutableArray<NSString *> *created) {
    // NEW-2: only ENOENT/ENOTDIR prove the path is absent — every other
    // open error is a FAILURE of that resource (EBUSY), not a skip.
    int fd = open(path.UTF8String, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            shdw_log("acquire %s: skip (absent: %s)", path.UTF8String, strerror(errno));
            return SHADOWD_STATUS_OK;
        }
        shdw_log("acquire %s: open failed (%s) — resource failure", path.UTF8String, strerror(errno));
        return SHADOWD_STATUS_EBUSY;
    }

    // WAL: resolve the vnode, then durably persist the mayBeHidden record
    // BEFORE the kernel write.
    uint64_t vnode = 0, vId = 0;
    if (!resolve_vnode_for_fd(fd, &vnode, &vId)) {
        shdw_log("acquire %s: vnode resolution failed", path.UTF8String);
        close(fd);
        return SHADOWD_STATUS_EBUSY;
    }
    if (!ledger_add_record(path.UTF8String, ownerKey.UTF8String, vnode, vId, 0 /*mayBeHidden*/)) {
        shdw_log("acquire %s: ledger write failed", path.UTF8String);
        close(fd);
        return SHADOWD_STATUS_EBUSY;
    }

    // Set VISSHADOW and verify by reread (A5): a failure AFTER the write
    // attempt may mean the vnode IS hidden — retain the fd and the WAL
    // record until a verified clear; never close an fd whose vnode may
    // carry VISSHADOW.
    vflag_result_t vr = vnode_set_flag(vnode, true);
    if (vr == VFLAG_FAILED_PRE) {
        // No write was attempted — safe to roll back.
        shdw_log("acquire %s: hide failed before write at 0x%llx", path.UTF8String, vnode);
        ledger_remove_path_records(path.UTF8String);
        close(fd);
        return SHADOWD_STATUS_EBUSY;
    }
    if (vr == VFLAG_MAYBE) {
        // Outcome unknown — keep fd + record, adopt as unverified.
        shdw_log("acquire %s: hide UNVERIFIED at 0x%llx — retaining fd + record", path.UTF8String, vnode);
        gResources[path] = [ShadowResource resourceWithFd:fd vnode:vnode vId:vId flagSet:YES verified:NO owner:ownerKey];
        [created addObject:path];
        return SHADOWD_STATUS_EBUSY;
    }

    // Mark the record durably hidden.  A16: if that fails, the client got
    // no success reply, so the resource must not remain hidden on its
    // behalf — tear it down (or retain as unverified if the clear cannot
    // be verified).
    if (!ledger_update_record(path.UTF8String, ownerKey.UTF8String, vnode, vId, 1 /*hidden*/)) {
        shdw_log("acquire %s: ledger state update failed — tearing down", path.UTF8String);
        if (vnode_set_flag(vnode, false) == VFLAG_OK) {
            ledger_remove_path_records(path.UTF8String);
            close(fd);
        } else {
            gResources[path] = [ShadowResource resourceWithFd:fd vnode:vnode vId:vId flagSet:YES verified:NO owner:ownerKey];
            [created addObject:path];
        }
        return SHADOWD_STATUS_EBUSY;
    }

    gResources[path] = [ShadowResource resourceWithFd:fd vnode:vnode vId:vId flagSet:YES verified:YES owner:ownerKey];
    [created addObject:path];
    shdw_log("hidden: %s (vnode 0x%llx v_id %llu)", path.UTF8String, vnode, vId);
    return SHADOWD_STATUS_OK;
}

// Hide every allowlisted path for one owner.  Dedup by resource: a second
// acquire of an already-hidden path only adds the owner — it does NOT
// reopen/rehide (spec).  A21: if ANY path fails, only THIS call's work is
// rolled back before returning EBUSY.
static uint32_t acquire_for_owner(NSString *ownerKey) {
    uint32_t gated = acquire_status_if_ready();
    if (gated != SHADOWD_STATUS_OK) return gated;

    uint32_t status = SHADOWD_STATUS_OK;
    NSMutableArray<NSString *> *created = [NSMutableArray array];   // resources this call created
    NSMutableArray<NSString *> *joined = [NSMutableArray array];    // pre-existing resources this call joined
    for (NSUInteger i = 0; i < kAllowlistCount; i++) {
        NSString *path = kAllowlist[i];
        ShadowResource *res = gResources[path];
        uint32_t ps;
        if (res) {
            ps = acquire_join_existing(res, path, ownerKey, joined);
        } else {
            ps = acquire_create_new(path, ownerKey, created);
        }
        if (ps != SHADOWD_STATUS_OK) status = ps;
    }

    // A21: partial acquisition — roll back ONLY this call's work before the
    // handler replies EBUSY with no lease.
    if (status != SHADOWD_STATUS_OK) {
        shdw_log("acquire: rolling back owner %s after partial failure", ownerKey.UTF8String);
        rollback_acquire(ownerKey, created, joined);
    }
    return status;
}

// Release every resource owned by this owner.  VISSHADOW is cleared only
// after the LAST owner exits/releases.
static uint32_t release_for_owner(NSString *ownerKey) {
    uint32_t status = SHADOWD_STATUS_OK;
    for (NSString *path in [gResources allKeys]) {
        ShadowResource *res = gResources[path];
        if (![res.owners containsObject:ownerKey]) continue;
        [res.owners removeObject:ownerKey];
        shdw_log("release %s: owner %s released", path.UTF8String, ownerKey.UTF8String);
        if (res.owners.count == 0 && res.flagSet) {
            if (!resource_teardown(res, path)) {
                // Clear failed — retain fd + record, retry later (spec).
                [gPendingReleases addObject:path];
                status = SHADOWD_STATUS_EBUSY;
            }
        }
    }
    return status;
}

// ---------------------------------------------------------------------------
// Ledger recovery (PATH-BASED only; runs on the kernel queue after krw init)
// ---------------------------------------------------------------------------

// A3: rebuild ONE ledger record — the logic now lives in recovery.m
// (shdw_recover_one_record), compiled verbatim into both the daemon and the
// test harness.

// A12/A13: returns false when recovery did not complete DURABLY (boot-mismatch
// wipe failed, or the final rewrite/wipe failed) — the feature must not be
// advertised READY in that case.
static bool recover_from_ledger(void) {
    NSString *boot = nil;
    NSArray<NSString *> *records = ledger_read(&boot);

    if (records.count == 0) {
        return true;   // nothing to reconcile, nothing to make durable
    }
    if (!boot || ![boot isEqualToString:gBootUUID]) {
        // Fresh kernel — vnodes were destroyed by the reboot.  Discard all
        // records WITHOUT any kernel writes (spec).
        shdw_log("ledger: boot session mismatch — discarding %lu records without kernel writes", (unsigned long)records.count);
        if (!ledger_wipe()) {
            shdw_log("ledger: wipe after boot mismatch FAILED — recovery not durable");
            return false;
        }
        return true;
    }
    shdw_log("ledger: boot session matches — reconciling %lu records", (unsigned long)records.count);

    NSMutableArray<NSString *> *kept = [NSMutableArray array];
    for (NSString *rec in records) {
        shdw_recover_one_record(rec, kept);
    }

    // A12: the final rewrite must succeed to be durable — a failure means
    // recovery is NOT durable and the feature must not be advertised READY.
    if (kept.count == 0) {
        if (!ledger_wipe()) {
            shdw_log("ledger: final wipe FAILED — recovery not durable");
            return false;
        }
    } else if (!ledger_write_lines(gBootUUID, kept)) {
        shdw_log("ledger: final rewrite FAILED — recovery not durable");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// IPC server (Mach, synchronous)
// ---------------------------------------------------------------------------

static mach_port_t gServerPort = MACH_PORT_NULL;
static mach_port_t gNotifyPort = MACH_PORT_NULL;
// gServerQueue, gLeases / gOwnerPortCounts are declared with the resource
// model (owner_gone needs them); populated in setup_ipc_server.

// Keep a send right to the client's reply port as the lease; install a
// dead-name notification; on the client's death the kernel notifies us and
// the owner's leases are released.  A17: leases are REFERENCE-COUNTED per
// owner — the owner is only removed when ALL of its reply ports are dead
// (a client timeout/retry can leave multiple live ports for one owner).
// A18: the previous notification right returned by the kernel is dropped.
static void install_lease(mach_port_name_t replyPort, NSString *ownerKey) {
    if (gLeases[@(replyPort)] != nil) {
        // A18: this message carried a fresh send right we will not keep —
        // drop the received uref.
        shdw_log("lease: port 0x%x already leased — deallocating duplicate send right", replyPort);
        mach_port_deallocate(mach_task_self(), replyPort);
        return;
    }
    mach_port_name_t previous = MACH_PORT_NULL;
    kern_return_t kr = mach_port_request_notification(mach_task_self(), replyPort,
                                                      MACH_NOTIFY_DEAD_NAME, 0,
                                                      gNotifyPort, MACH_MSG_TYPE_MAKE_SEND_ONCE,
                                                      &previous);
    if (previous != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), previous);
    }
    if (kr != KERN_SUCCESS) {
        // The lease is already dead (client gone before we could arm the
        // notification) — this port contributes nothing; the polling
        // fallback will reap the owner if no other lease survives.
        // A18: drop the received send right on the failure path too.
        shdw_log("lease: dead-name request failed (0x%x) for owner %s", kr, ownerKey.UTF8String);
        mach_port_deallocate(mach_task_self(), replyPort);
        return;
    }
    gLeases[@(replyPort)] = ownerKey;
    gOwnerPortCounts[ownerKey] = @([gOwnerPortCounts[ownerKey] intValue] + 1);
    shdw_log("lease: installed for owner %s (reply port 0x%x, count %d)",
             ownerKey.UTF8String, replyPort, [gOwnerPortCounts[ownerKey] intValue]);
}

static void send_reply(shadowd_request_t *req, uint32_t status) {
    shadowd_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    reply.header.msgh_size = sizeof(shadowd_reply_t);
    reply.header.msgh_remote_port = req->replyPort.name;
    reply.header.msgh_local_port = MACH_PORT_NULL;
    reply.magic = SHADOWD_MAGIC;
    reply.version = SHADOWD_VERSION;
    reply.requestId = req->requestId;
    reply.status = status;

    // A19: bounded send — a malicious or full client reply queue must not be
    // able to block the server queue indefinitely.
    kern_return_t kr = mach_msg(&reply.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                reply.header.msgh_size, 0, MACH_PORT_NULL, 5000, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        shdw_log("reply: mach_msg failed (0x%x)", kr);
    }
}

// A5: reply and drop the received reply-port send right (the common
// handle_request tail).
static void reply_and_release(shadowd_request_t *req, uint32_t status) {
    send_reply(req, status);
    mach_port_deallocate(mach_task_self(), req->replyPort.name);
}

static void handle_request(shadowd_request_t *req) {
    if (req->magic != SHADOWD_MAGIC) {
        shdw_log("request: bad magic 0x%x", req->magic);
        mach_msg_destroy(&req->header);
        return;
    }
    if (req->version != SHADOWD_VERSION) {
        shdw_log("request: unsupported version %u", req->version);
        reply_and_release(req, SHADOWD_STATUS_ENOTSUP);
        return;
    }
    if (req->op == SHADOWD_OP_PING) {
        reply_and_release(req, SHADOWD_STATUS_OK);
        return;
    }
    // Health query for the Settings bundle: reports krw readiness so the
    // VnodeHiding toggle can be gated on real daemon capability instead of
    // guessing from file presence. Status mapping: READY → OK (0),
    // INIT → EBUSY (still starting), DISABLED → ENOTSUP (krw failed).
    if (req->op == SHADOWD_OP_STATUS) {
        krw_state_t st = atomic_load(&gKrwState);
        uint32_t status;
        switch (st) {
            case KRW_READY:
                status = SHADOWD_STATUS_OK;
                break;
            case KRW_INIT:
                status = SHADOWD_STATUS_EBUSY;
                break;
            default:
                status = SHADOWD_STATUS_ENOTSUP;
                break;
        }
        reply_and_release(req, status);
        return;
    }

    // Identity comes ONLY from the kernel-provided audit trailer.
    mach_msg_audit_trailer_t *trailer =
        (mach_msg_audit_trailer_t *)((uint8_t *)req + round_msg(req->header.msgh_size));
    audit_token_t token = trailer->msgh_audit;
    pid_t pid = (pid_t)token.val[5];   // audit_token_to_pid layout
    uid_t euid = (uid_t)token.val[1];  // audit_token_to_euid layout
    if (euid == 0 || pid <= 0) {
        shdw_log("request: rejected (pid %d, euid %u)", pid, euid);
        reply_and_release(req, SHADOWD_STATUS_EPERM);
        return;
    }

    // A15: the owner identity REQUIRES the process start time — without it
    // the owner key degrades to pid-0-0 and PID reuse defeats the lease.
    // Reject the request rather than weaken identity.
    uint64_t sec = 0, usec = 0;
    if (!owner_start_time(pid, &sec, &usec)) {
        shdw_log("request: owner start time unavailable for pid %d — rejecting", pid);
        reply_and_release(req, SHADOWD_STATUS_EBUSY);
        return;
    }
    NSString *ownerKey = owner_key(pid, sec, usec);

    if (req->op == SHADOWD_OP_ACQUIRE) {
        __block uint32_t status = SHADOWD_STATUS_ENOTSUP;
        dispatch_sync(gKernelQueue, ^{
            status = acquire_for_owner(ownerKey);
        });
        // Reply only after the hide is verified; the reply port becomes the
        // lease only on success.
        send_reply(req, status);
        if (status == SHADOWD_STATUS_OK) {
            install_lease(req->replyPort.name, ownerKey);
        } else {
            mach_port_deallocate(mach_task_self(), req->replyPort.name);
        }
        return;
    }
    if (req->op == SHADOWD_OP_RELEASE) {
        __block uint32_t status = SHADOWD_STATUS_OK;
        dispatch_sync(gKernelQueue, ^{
            status = release_for_owner(ownerKey);
        });
        reply_and_release(req, status);
        return;
    }
    shdw_log("request: unknown op %u", req->op);
    reply_and_release(req, SHADOWD_STATUS_ENOTSUP);
}

static void server_receive(void) {
    static uint8_t gRecvBuf[sizeof(shadowd_request_t) + MAX_TRAILER_SIZE]
        __attribute__((aligned(16)));
    shadowd_request_t *req = (shadowd_request_t *)gRecvBuf;

    mach_msg_options_t options = MACH_RCV_MSG |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
    kern_return_t kr = mach_msg(&req->header, options, 0, sizeof(gRecvBuf),
                                gServerPort, 0, MACH_PORT_NULL);
    if (kr == MACH_RCV_TIMED_OUT) {
        return;
    }
    if (kr != KERN_SUCCESS) {
        shdw_log("server: receive failed (0x%x)", kr);
        return;
    }

    // A20: strict message validation.  Anything malformed is destroyed
    // (mach_msg_destroy drops the reply-port send right) and dropped —
    // never parsed, never replied to.
    if (req->header.msgh_size != sizeof(shadowd_request_t)) {
        shdw_log("server: bad message size %u (expected %zu)", req->header.msgh_size, sizeof(shadowd_request_t));
        if (req->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) mach_msg_destroy(&req->header);
        return;
    }
    if (!(req->header.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        shdw_log("server: message is not complex (no reply port)");
        return;
    }
    if (req->msgh_body.msgh_descriptor_count != 1) {
        shdw_log("server: descriptor count %u (expected 1)", req->msgh_body.msgh_descriptor_count);
        mach_msg_destroy(&req->header);
        return;
    }
    // A20: descriptor disposition — the SENDER specifies MACH_MSG_TYPE_MAKE_SEND,
    // but the RECEIVER sees the realized disposition MACH_MSG_TYPE_PORT_SEND
    // (the kernel converts MAKE_SEND on delivery).  Accept both so every
    // valid client request passes.
    if (req->replyPort.type != MACH_MSG_PORT_DESCRIPTOR ||
        (req->replyPort.disposition != MACH_MSG_TYPE_PORT_SEND &&
         req->replyPort.disposition != MACH_MSG_TYPE_MAKE_SEND)) {
        shdw_log("server: bad reply port descriptor (type %u, disposition %u)",
                 req->replyPort.type, req->replyPort.disposition);
        mach_msg_destroy(&req->header);
        return;
    }
    // A20: the received port NAME must be a live name.
    if (req->replyPort.name == MACH_PORT_NULL || req->replyPort.name == MACH_PORT_DEAD) {
        shdw_log("server: invalid reply port name 0x%x", req->replyPort.name);
        mach_msg_destroy(&req->header);
        return;
    }
    // A20: the audit trailer must fit in the receive buffer AND actually be
    // present with the expected format/size (the receive options request
    // MACH_RCV_TRAILER_AUDIT; a missing/malformed trailer is rejected).
    mach_msg_audit_trailer_t *tr = (mach_msg_audit_trailer_t *)((uint8_t *)req + round_msg(req->header.msgh_size));
    if (round_msg(req->header.msgh_size) + sizeof(mach_msg_audit_trailer_t) > sizeof(gRecvBuf)) {
        shdw_log("server: audit trailer out of bounds");
        mach_msg_destroy(&req->header);
        return;
    }
    if (tr->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
        tr->msgh_trailer_size < sizeof(mach_msg_audit_trailer_t)) {
        shdw_log("server: audit trailer missing or malformed (type %u, size %u)",
                 tr->msgh_trailer_type, tr->msgh_trailer_size);
        mach_msg_destroy(&req->header);
        return;
    }
    handle_request(req);
}

static void setup_ipc_server(void) {
    gServerQueue = dispatch_queue_create("me.jjolano.shadowd.server", NULL);
    gLeases = [NSMutableDictionary dictionary];
    gOwnerPortCounts = [NSMutableDictionary dictionary];

    kern_return_t kr = bootstrap_check_in(bootstrap_port, MACH_SERVICE_NAME, &gServerPort);
    if (kr != KERN_SUCCESS) {
        shdw_log("bootstrap_check_in(%s) failed (0x%x) — serving nothing", MACH_SERVICE_NAME, kr);
        return;
    }
    shdw_log("service registered: %s", MACH_SERVICE_NAME);

    dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV,
                                                   (uintptr_t)gServerPort, 0, gServerQueue);
    dispatch_source_set_event_handler(src, ^{
        server_receive();
    });
    dispatch_resume(src);

    // Dead-name notification port.
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gNotifyPort);
    dispatch_source_t notifySrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV,
                                                         (uintptr_t)gNotifyPort, 0, gServerQueue);
    dispatch_source_set_event_handler(notifySrc, ^{
        mach_dead_name_notification_t notif;
        kern_return_t kr2 = mach_msg(&notif.not_header, MACH_RCV_MSG, 0, sizeof(notif),
                                     gNotifyPort, 0, MACH_PORT_NULL);
        if (kr2 == MACH_RCV_TIMED_OUT) return;
        if (kr2 != KERN_SUCCESS) {
            shdw_log("dead-name: receive failed (0x%x)", kr2);
            return;
        }
        // This SDK's mach_dead_name_notification_t carries the dead name
        // directly (mach_port_name_t not_port, after the NDR).
        mach_port_name_t deadName = notif.not_port;
        // A18: the dead-name right (and its uref) is consumed by the
        // notification — deallocate it on EVERY path, including the
        // unknown-port case, so the name does not leak.
        mach_port_deallocate(mach_task_self(), deadName);
        NSString *ownerKey = gLeases[@(deadName)];
        if (!ownerKey) {
            shdw_log("dead-name: unknown port 0x%x", deadName);
            return;
        }
        [gLeases removeObjectForKey:@(deadName)];
        // A17: reference-counted leases — the owner is removed only when ALL
        // of its reply ports are dead.
        int remaining = [gOwnerPortCounts[ownerKey] intValue] - 1;
        shdw_log("dead-name: lease for owner %s died (%d remaining)", ownerKey.UTF8String, remaining);
        if (remaining <= 0) {
            [gOwnerPortCounts removeObjectForKey:ownerKey];
            dispatch_async(gKernelQueue, ^{
                owner_gone(ownerKey);
            });
        } else {
            gOwnerPortCounts[ownerKey] = @(remaining);
        }
    });
    dispatch_resume(notifySrc);
}

static void setup_poll_timer(void) {
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gKernelQueue);
    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, POLL_INTERVAL * NSEC_PER_SEC),
                              POLL_INTERVAL * NSEC_PER_SEC,
                              2 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        sweep_owners();
    });
    dispatch_resume(timer);
}

// ---------------------------------------------------------------------------
// Shutdown (SIGTERM/SIGINT)
// ---------------------------------------------------------------------------

// A7: SIGTERM/SIGINT shutdown.  A failed/ambiguous clear must prevent fd
// close, ledger wipe and a SUCCESSFUL exit — retry until every clear is
// verified; only exit(0) when all clears verified AND the ledger removal is
// durable.  Ordering (A7b): the durable ledger wipe happens BEFORE any
// anchored fd is closed — closing the last anchor of a still-flagged vnode
// (kernel reclaim hazard) must never lose the recovery record.  On the
// non-zero exit path (A7a): a FINAL clear sweep runs; only fds whose clear
// VERIFIED are closed — ambiguous/failed clears keep their fd open
// (intentional leak), and the ledger is retained for restart recovery.
static void shutdown_daemon(void) {
    shdw_log("shutdown: clearing all VISSHADOW flags");

    // Phase 1: verify-clear every flag (retry with backoff).
    bool allVerified = false;
    for (int attempt = 1; attempt <= SHUTDOWN_MAX_ATTEMPTS; attempt++) {
        allVerified = true;
        for (NSString *path in [gResources allKeys]) {
            ShadowResource *res = gResources[path];
            if (!res.flagSet) continue;
            if (res.fd >= 0) {
                if (vnode_set_flag(res.vnode, false) == VFLAG_OK) {
                    res.flagSet = NO;
                    shdw_log("shutdown: cleared %s", path.UTF8String);
                } else {
                    shdw_log("shutdown: clear UNVERIFIED for %s — retaining", path.UTF8String);
                    allVerified = false;
                }
            } else {
                // Restart-adopted: read-only saved vnode — fresh-open only (A8).
                if (adopted_clear(res, path)) {
                    res.flagSet = NO;
                    shdw_log("shutdown: cleared (adopted, fresh fd) %s", path.UTF8String);
                } else {
                    shdw_log("shutdown: adopted resource %s not clearable — retaining", path.UTF8String);
                    allVerified = false;
                }
            }
        }
        if (allVerified) break;
        shdw_log("shutdown: %d/%d — not all clears verified, retrying in 2s", attempt, SHUTDOWN_MAX_ATTEMPTS);
        sleep(2);
    }

    if (allVerified) {
        // Phase 2 (A7b): durable ledger wipe BEFORE closing any anchored fd —
        // a failed wipe must not destroy the recovery record for still-flagged
        // vnodes; fds are closed only after the removal is durable.
        for (int w = 1; w <= SHUTDOWN_MAX_ATTEMPTS; w++) {
            if (ledger_wipe()) {
                for (NSString *path in [gResources allKeys]) {
                    ShadowResource *res = gResources[path];
                    if (res.fd >= 0) {
                        close(res.fd);
                        res.fd = -1;
                    }
                }
                shdw_log("shadowd exiting");
                exit(0);
            }
            shdw_log("shutdown: ledger wipe failed (%d/%d) — retrying in 2s", w, SHUTDOWN_MAX_ATTEMPTS);
            sleep(2);
        }
        shdw_log("shutdown: ledger wipe never durable — retaining ledger and fds");
    }

    // Phase 3 (A7a): final clear sweep, then close ONLY fds whose clear
    // VERIFIED; ambiguous/failed clears keep their fd open (intentional
    // leak — closing the last anchor of a maybe-flagged vnode is a kernel
    // reclaim hazard).  The ledger is retained for restart recovery.
    shdw_log("shutdown: final clear sweep");
    for (NSString *path in [gResources allKeys]) {
        ShadowResource *res = gResources[path];
        if (res.fd >= 0 && res.flagSet) {
            if (vnode_set_flag(res.vnode, false) == VFLAG_OK) {
                res.flagSet = NO;
                shdw_log("shutdown: final clear verified for %s", path.UTF8String);
            } else {
                shdw_log("shutdown: %s clear still unverified — fd NOT closed (intentional leak, ledger retained)", path.UTF8String);
            }
        }
        if (res.fd >= 0 && !res.flagSet) {
            close(res.fd);
            res.fd = -1;
            shdw_log("shutdown: closed fd for %s (clear verified)", path.UTF8String);
        }
    }
    shdw_log("shutdown: exiting non-zero — ledger retained for restart recovery");
    exit(1);
}

static void setup_signal_handlers(void) {
    // Dispatch sources need the default action out of the way.
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);

    dispatch_source_t term = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,
                                                    SIGTERM, 0, gKernelQueue);
    dispatch_source_set_event_handler(term, ^{
        shutdown_daemon();
    });
    dispatch_resume(term);

    dispatch_source_t intr = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,
                                                    SIGINT, 0, gKernelQueue);
    dispatch_source_set_event_handler(intr, ^{
        shutdown_daemon();
    });
    dispatch_resume(intr);
}

// ---------------------------------------------------------------------------
// KRW init (background, with backoff) → recovery → ready
// ---------------------------------------------------------------------------

static void krw_init_background(void) {
    @autoreleasepool {
        // Row offsets + t1sz_boot must be in place before ANY krw work
        // (the tfp0 allproc scan reads off_p_pid).
        if (offset_init() != 0) {
            shdw_log("krw: offset_init failed — feature disabled");
            atomic_store(&gKrwState, KRW_DISABLED);
            return;
        }

        bool ok = false;

        if (is_arm64e()) {
            shdw_log("krw: arm64e — libjailbreak path");
            for (int attempt = 1; attempt <= KRW_RETRY_MAX; attempt++) {
                if (krw_init_libjb_once() == 0) {
                    ok = true;
                    break;
                }
                if (attempt < KRW_RETRY_MAX) {
                    shdw_log("krw: libjailbreak attempt %d/%d failed — retrying in %ds",
                             attempt, KRW_RETRY_MAX, KRW_RETRY_INTERVAL);
                    sleep(KRW_RETRY_INTERVAL);
                }
            }
            if (ok) {
                gKrwMode = KRW_LIBJB;
            } else {
                // Spec: arm64e without libjailbreak → feature disabled, fail soft.
                shdw_log("krw: libjailbreak unavailable after %ds — feature disabled", KRW_RETRY_INTERVAL * KRW_RETRY_MAX);
            }
        } else {
            // arm64 (A8-A11): libjailbreak first when the dylib is present
            // (Dopamine-arm64 forks expose the same jbdInitPPLRW/kreadbuf/
            // proc_find API as arm64e — proc_find resolves our own proc
            // WITHOUT the kernel-image pfinder scan the libkrw/tfp0 paths
            // require, and the libjb physrw primitives read live kernel
            // objects directly).  An absent dylib (plain palera1n) falls
            // straight through to libkrw → tfp0.
            if (krw_libjb_present()) {
                shdw_log("krw: arm64 libjailbreak present — trying");
                for (int attempt = 1; attempt <= KRW_RETRY_MAX; attempt++) {
                    if (krw_init_libjb_once() == 0) {
                        gKrwMode = KRW_LIBJB;
                        ok = true;
                        break;
                    }
                    if (attempt < KRW_RETRY_MAX) {
                        shdw_log("krw: libjailbreak attempt %d/%d failed — retrying in %ds",
                                 attempt, KRW_RETRY_MAX, KRW_RETRY_INTERVAL);
                        sleep(KRW_RETRY_INTERVAL);
                    }
                }
            }
            if (!ok) {
                if (krw_init_libkrw_once() == 0) {
                    gKrwMode = KRW_LIBKRW;
                    ok = true;
                    shdw_log("krw: libkrw backend ready");
                } else if (krw_init_tfp0() == 0) {
                    gKrwMode = KRW_TFP0;
                    ok = true;
                } else {
                    shdw_log("krw: libkrw + tfp0 init failed — feature disabled");
                }
            }
        }

        if (ok) {
            // A13: publish READY only AFTER ledger recovery has COMPLETED
            // DURABLY — recovery runs synchronously on the kernel queue first
            // (deadlock-safe: acquires return EBUSY immediately, A22).  On
            // non-durable recovery the feature is disabled (A12).
            __block bool recovered = false;
            dispatch_sync(gKernelQueue, ^{
                recovered = recover_from_ledger();
            });
            if (recovered) {
                atomic_store(&gKrwState, KRW_READY);
                shdw_log("krw: ready (mode %s)", gKrwMode == KRW_LIBJB ? "libjailbreak" : (gKrwMode == KRW_LIBKRW ? "libkrw" : "tfp0"));
            } else {
                shdw_log("krw: ledger recovery not durable — feature disabled");
                atomic_store(&gKrwState, KRW_DISABLED);
            }
        } else {
            atomic_store(&gKrwState, KRW_DISABLED);
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    @autoreleasepool {
        shdw_log("shadowd starting (pid %d)", getpid());

        gIsRootless = (access("/var/jb", F_OK) == 0);
        shdw_log("rootless: %s", gIsRootless ? "yes" : "no");

        gKernelQueue = dispatch_queue_create("me.jjolano.shadowd.kernel", NULL);
        gResources = [NSMutableDictionary dictionary];
        gPendingReleases = [NSMutableSet set];

        if (!version_gate()) {
            // Hard ceiling: feature disabled for this run; the daemon stays
            // alive but idles (IPC still answers ENOTSUP).
            atomic_store(&gKrwState, KRW_DISABLED);
        } else {
            char uuid[128] = {0};
            if (!get_boot_uuid(uuid, sizeof(uuid))) {
                // Spec: boot UUID unavailable/empty → disable the feature.
                shdw_log("kern.bootsessionuuid unavailable — feature disabled");
                atomic_store(&gKrwState, KRW_DISABLED);
            } else {
                gBootUUID = [NSString stringWithUTF8String:uuid];
                shdw_log("boot session: %s", uuid);
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                    krw_init_background();
                });
            }
        }

        setup_ipc_server();
        setup_poll_timer();
        setup_signal_handlers();

        shdw_log("shadowd ready");
        dispatch_main();
    }
    return 0;
}
