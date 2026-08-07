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

#include "../common.h"   // BUNDLE_ID, MACH_SERVICE_NAME, SHADOW_PREFS_PLIST

// SDK 16.5's mach/bootstrap.h is a compatibility stub — declare the classic
// prototype directly (name_t decays to const char *).
extern kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service_name, mach_port_t *service_port);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define VISSHADOW 0x008000

// Offset table (corrected per review; these fix the rejected vnode.x rows):
//   iOS 16 uses p_pid 0x60 (Dopamine libjailbreak info.c) — the rejected
//   review had 0x68.  iOS 12 f_fglob is 0x8.  vnode offsets are constant.
#define OFF_VNODE_V_FLAGS    0x54
#define OFF_VNODE_V_USECOUNT 0x60   // read-only validation only — never edited
#define OFF_VNODE_V_IOCOUNT  0x64   // read-only validation only — never edited
#define OFF_VNODE_V_TYPE     0x70   // uint16; jelbrekLib offsetof.c
#define OFF_VNODE_V_ID       0x74   // uint32; jelbrekLib offsetof.c
// fileglob/fileops offsets (XNU layout: f_data at 0x38 ⇒ f_ops at 0x30;
// fileops = 8 fn pointers + int fo_type at 0x40; DTYPE_VNODE == 1).
#define OFF_FG_OPS     0x30
#define OFF_FO_TYPE    0x40
#define DTYPE_VNODE    1

// Vnode types (vnode.h)
#define VNON 0
#define VREG 1
#define VDIR 2
#define VLNK 10

#ifndef kCFCoreFoundationVersionNumber_iOS_12_0
#define kCFCoreFoundationVersionNumber_iOS_12_0 (1535.12)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_13_0
#define kCFCoreFoundationVersionNumber_iOS_13_0 (1656)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_14_0
#define kCFCoreFoundationVersionNumber_iOS_14_0 (1740)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_15_0
#define kCFCoreFoundationVersionNumber_iOS_15_0 (1854)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_15_2
#define kCFCoreFoundationVersionNumber_iOS_15_2 (1856.105)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_17_0
#define kCFCoreFoundationVersionNumber_iOS_17_0 (2050)
#endif

// IPC protocol (raw mach_msg, versioned).  Client → server carries a reply
// port (MACH_MSG_TYPE_MAKE_SEND); server → client is a plain message to that
// port.  NO paths, NO client-supplied pid.
#define SHADOWD_MAGIC   0x53484457  // 'SHDW'
#define SHADOWD_VERSION 1

typedef enum {
    SHADOWD_OP_PING    = 1,
    SHADOWD_OP_ACQUIRE = 2,
    SHADOWD_OP_RELEASE = 3,
} shadowd_op_t;

// Status codes (errno values): 0 ok | EPERM | ENOTSUP | EBUSY
#define SHADOWD_STATUS_OK      0
#define SHADOWD_STATUS_EPERM   EPERM
#define SHADOWD_STATUS_ENOTSUP ENOTSUP
#define SHADOWD_STATUS_EBUSY   EBUSY

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t replyPort;   // MACH_MSG_TYPE_MAKE_SEND
    uint32_t magic;
    uint32_t version;
    uint32_t op;
    uint32_t requestId;
} shadowd_request_t;

typedef struct {
    mach_msg_header_t header;
    uint32_t magic;
    uint32_t version;
    uint32_t requestId;
    uint32_t status;
} shadowd_reply_t;

// Fixed compiled allowlist.  NOTE (review finding): Shadow.dylib itself,
// shadowd, its plist and the ledger are deliberately NOT hidden — hiding the
// recovery dylib creates a respring deadlock; dyld-level filtering already
// covers the dylib name.
static NSString *const kAllowlist[] = {
    @(SHADOW_PREFS_PLIST),                                          // /var/mobile/... (rootful AND rootless)
    @"/var/jb/var/mobile/Library/Preferences/" BUNDLE_ID ".plist",  // rootless-prefixed variant
    @"/Library/PreferenceBundles/ShadowSettings.bundle",            // rootful
    @"/var/jb/Library/PreferenceBundles/ShadowSettings.bundle",     // rootless
};
static const NSUInteger kAllowlistCount = sizeof(kAllowlist) / sizeof(kAllowlist[0]);

#define KRW_RETRY_INTERVAL 2
#define KRW_RETRY_MAX      15   // 2s * 15 = 30s
#define POLL_INTERVAL      10   // seconds, owner-death fallback + release retry

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

static void shdw_log(const char *fmt, ...) {
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

static bool gIsRootless = false;

// ---------------------------------------------------------------------------
// Version gate (hard ceiling: iOS 15.0–16.6.1 ONLY)
// ---------------------------------------------------------------------------

// Parse "Darwin Kernel Version 22.6.0: ..." from kern.version.
static bool darwin_version(int *major, int *minor) {
    char kern_version[512] = {};
    size_t size = sizeof(kern_version);
    if (sysctlbyname("kern.version", &kern_version, &size, NULL, 0) != 0) {
        return false;
    }
    return sscanf(kern_version, "Darwin Kernel Version %d.%d", major, minor) == 2;
}

static bool version_gate(void) {
    double cf = kCFCoreFoundationVersionNumber;
    int dmaj = 0, dmin = 0;
    bool haveDarwin = darwin_version(&dmaj, &dmin);

    shdw_log("kCFCoreFoundationVersionNumber: %.3f%s", cf,
             haveDarwin ? ", Darwin Kernel Version" : "");
    if (haveDarwin) {
        shdw_log("Darwin %d.%d", dmaj, dmin);
    }

    if (cf < kCFCoreFoundationVersionNumber_iOS_15_0) {
        shdw_log("UNSUPPORTED: iOS < 15.0 (CF %.3f) — feature disabled", cf);
        return false;
    }
    if (cf >= kCFCoreFoundationVersionNumber_iOS_17_0) {
        shdw_log("UNSUPPORTED: iOS >= 17.0 (CF %.3f) — feature disabled", cf);
        return false;
    }
    if (haveDarwin) {
        // iOS 15.x = Darwin 21, iOS 16.0–16.6.x = Darwin 22.0–22.6.
        // Darwin 22.7 = iOS 16.7+ → above the ceiling.
        if (dmaj < 21 || dmaj > 22) {
            shdw_log("UNSUPPORTED: Darwin %d.%d — feature disabled", dmaj, dmin);
            return false;
        }
        if (dmaj == 22 && dmin > 6) {
            shdw_log("UNSUPPORTED: Darwin 22.%d (iOS > 16.6.1) — feature disabled", dmin);
            return false;
        }
    } else {
        shdw_log("kern.version unavailable — relying on CF version floor/ceiling only");
    }
    shdw_log("version gate: supported (iOS 15.0–16.6.1)");
    return true;
}

// ---------------------------------------------------------------------------
// Offsets (corrected table — implement exactly as specified)
// ---------------------------------------------------------------------------

static uint32_t off_p_pid = 0;
static uint32_t off_p_pfd = 0;
static uint32_t off_fd_ofiles = 0;
static uint32_t off_fp_fglob = 0;
static uint32_t off_fg_data = 0;
static unsigned long long t1sz_boot = 0;

// true when the fd table is inline in filedesc (iOS 15+), false for the
// ptr-style walk (filedesc + off_fd_ofiles → array, iOS 12-14).
static bool gFdTableInline = false;

static bool is_arm64e(void) {
    cpu_subtype_t subtype;
    size_t cpusz = sizeof(cpu_subtype_t);
    sysctlbyname("hw.cpusubtype", &subtype, &cpusz, NULL, 0);
    return (subtype == 2 /* CPU_SUBTYPE_ARM64E */);
}

// t1sz_boot + row dispatch (kernel.m verbatim).
static int offset_init(void) {
    if (is_arm64e()) {
        char kern_version[512] = {};
        size_t size = sizeof(kern_version);
        sysctlbyname("kern.version", &kern_version, &size, NULL, 0);
        if (strstr(kern_version, "T8120") != NULL || strstr(kern_version, "T8103") != NULL || strstr(kern_version, "T8112") != NULL)
            t1sz_boot = 17;
        else
            t1sz_boot = 25;
    } else {
        t1sz_boot = 0;
    }

    // Rows iOS 12/13/14 are unreachable at runtime (version gate is
    // 15.0-16.6.1) but implemented per the corrected spec table.
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_2) {
        // ios 15.2 ~ 16.6.1 — p_pid 0x60 per Dopamine libjailbreak info.c
        shdw_log("offsets: iOS 15.2+ (p_pid 0x60, p_pfd 0xf8)");
        off_p_pid = 0x60;
        off_p_pfd = 0xf8;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        gFdTableInline = true;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_0) {
        // ios 15.0-15.1.1
        shdw_log("offsets: iOS 15.0-15.1.1 (p_pid 0x68, p_pfd 0x100)");
        off_p_pid = 0x68;
        off_p_pfd = 0x100;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        gFdTableInline = true;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_14_0) {
        // ios 14 (vnb-zero row)
        off_p_pid = 0x68;
        off_p_pfd = 0xf8;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        gFdTableInline = false;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0) {
        // ios 13 (plus007 kstruct_offsets_13_0)
        off_p_pid = 0x68;
        off_p_pfd = 0x108;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        gFdTableInline = false;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
        // ios 12 (plus007 kstruct_offsets_12_0 — f_fglob 0x8, ptr-style walk)
        off_p_pid = 0x60;
        off_p_pfd = 0x100;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x8;
        off_fg_data = 0x38;
        gFdTableInline = false;
        return 0;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// KRW backends
// ---------------------------------------------------------------------------

typedef enum {
    KRW_NONE = 0,
    KRW_LIBJB,   // Dopamine: libjailbreak.dylib (PPL r/w)
    KRW_TFP0     // palera1n/legacy: task_for_pid(0) + mach_vm r/w
} krw_mode_t;

typedef enum {
    KRW_INIT = 0,      // init in progress (background, with backoff)
    KRW_READY = 1,
    KRW_DISABLED = -1,
} krw_state_t;

static krw_mode_t gKrwMode = KRW_NONE;
static volatile krw_state_t gKrwState = KRW_INIT;
static dispatch_semaphore_t gKrwReadySem;
static uint64_t gOurProc = 0;   // tfp0 path: cached own-proc from allproc scan

// ---- libjailbreak (Dopamine) ----
static void *gLibJB = NULL;
static int (*libjb_jbdInitPPLRW)(void) = NULL;
static uint64_t (*libjb_kread8)(uint64_t) = NULL;
static uint16_t (*libjb_kread16)(uint64_t) = NULL;
static uint32_t (*libjb_kread32)(uint64_t) = NULL;
static uint64_t (*libjb_kread64)(uint64_t) = NULL;
static uint64_t (*libjb_kread_ptr)(uint64_t) = NULL;
static int (*libjb_kreadbuf)(uint64_t, void *, size_t) = NULL;
static void (*libjb_kwrite8)(uint64_t, uint8_t) = NULL;
static void (*libjb_kwrite16)(uint64_t, uint16_t) = NULL;
static void (*libjb_kwrite32)(uint64_t, uint32_t) = NULL;
static void (*libjb_kwrite64)(uint64_t, uint64_t) = NULL;
static int (*libjb_kwrite_ptr)(uint64_t, uint64_t, uint16_t) = NULL;
static int (*libjb_kwritebuf)(uint64_t, const void *, size_t) = NULL;
static uint64_t (*libjb_proc_find)(pid_t) = NULL;
static int (*libjb_proc_rele)(uint64_t) = NULL;

// dlsym → typed function pointer without -Werror conversion issues.
#define DL_SYM(var, name) do { *(void **)(&(var)) = dlsym(gLibJB, (name)); } while (0)

// One init attempt: dlopen + dlsym all symbols + jbdInitPPLRW.  Retried by
// the caller every 2s up to 30s.  The daemon is root, so no getuid hooking
// is needed (the jailed caller protection doesn't apply).
static int krw_init_libjb_once(void) {
    if (!gLibJB) {
        gLibJB = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);
        if (!gLibJB) {
            shdw_log("libjailbreak: dlopen failed: %s", dlerror());
            return 1;
        }
    }
    DL_SYM(libjb_jbdInitPPLRW, "jbdInitPPLRW");
    DL_SYM(libjb_kread8, "kread8");
    DL_SYM(libjb_kread16, "kread16");
    DL_SYM(libjb_kread32, "kread32");
    DL_SYM(libjb_kread64, "kread64");
    DL_SYM(libjb_kread_ptr, "kread_ptr");
    DL_SYM(libjb_kreadbuf, "kreadbuf");
    DL_SYM(libjb_kwrite8, "kwrite8");
    DL_SYM(libjb_kwrite16, "kwrite16");
    DL_SYM(libjb_kwrite32, "kwrite32");
    DL_SYM(libjb_kwrite64, "kwrite64");
    DL_SYM(libjb_kwrite_ptr, "kwrite_ptr");
    DL_SYM(libjb_kwritebuf, "kwritebuf");
    DL_SYM(libjb_proc_find, "proc_find");
    DL_SYM(libjb_proc_rele, "proc_rele");

    if (!libjb_jbdInitPPLRW || !libjb_kreadbuf || !libjb_kwritebuf ||
        !libjb_kread32 || !libjb_kread64 || !libjb_kwrite32 || !libjb_kwrite64 ||
        !libjb_kread_ptr || !libjb_kwrite_ptr || !libjb_proc_find) {
        shdw_log("libjailbreak: missing symbols (jbdInitPPLRW=%p kreadbuf=%p kwritebuf=%p kread_ptr=%p kwrite_ptr=%p proc_find=%p)",
                 libjb_jbdInitPPLRW, libjb_kreadbuf, libjb_kwritebuf,
                 libjb_kread_ptr, libjb_kwrite_ptr, libjb_proc_find);
        return 1;
    }

    // jbdInitPPLRW may fail while jailbreakd is still coming up — the caller
    // retries with backoff.
    int ret = libjb_jbdInitPPLRW();
    if (ret != 0) {
        shdw_log("libjailbreak: jbdInitPPLRW failed (ret %d)", ret);
        return 1;
    }
    shdw_log("libjailbreak: jbdInitPPLRW ok");
    return 0;
}

// ---- tfp0 backend (plus007 main.m verbatim) ----
typedef uint64_t kaddr_t;

// mach_vm_* forward declarations (plus007 main.m verbatim — the SDK 16.5
// public mach_vm.h omits mach_vm_region / mach_vm_machine_attribute).
kern_return_t
        mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
        mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
        mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
        mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

#define VM_KERNEL_LINK_ADDRESS (0xFFFFFFF007004000ULL)
#define VM_KERN_MEMORY_CPU (9)

#ifdef __arm64e__
# define CPU_DATA_RTCLOCK_DATAP_OFF (0x190)
#else
# define CPU_DATA_RTCLOCK_DATAP_OFF (0x198)
#endif

#ifndef MIN
# define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef SEG_TEXT_EXEC
# define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef SECT_CSTRING
# define SECT_CSTRING "__cstring"
#endif

// instruction-decode helpers (plus007 main.m verbatim)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))

typedef struct {
    struct section_64 s64;
    char *data;
} sec_64_t;

typedef struct {
    sec_64_t sec_text, sec_cstring;
} pfinder_t;

static kaddr_t allproc = 0;
static task_t tfp0 = MACH_PORT_NULL;

static uint32_t extract32(uint32_t val, unsigned start, unsigned len) {
    return (val >> start) & (~0U >> (32U - len));
}

static uint64_t sextract64(uint64_t val, unsigned start, unsigned len) {
    return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static kern_return_t init_tfp0(void) {
    kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
    mach_port_t host;
    pid_t pid;

    if (ret != KERN_SUCCESS) {
        host = mach_host_self();
        if (MACH_PORT_VALID(host)) {
            shdw_log("tfp0: host special port path (unc0ver-style)");
            ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
            return ret;
        }
        mach_port_deallocate(mach_task_self(), host);
    }
    if (ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
        if (pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
            return ret;
        }
        mach_port_deallocate(mach_task_self(), tfp0);
    }
    shdw_log("tfp0: failed to init");
    return KERN_FAILURE;
}

static kern_return_t kread_buf_tfp0(kaddr_t addr, void *buf, mach_vm_size_t sz) {
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_vm_size_t read_sz, out_sz = 0;

    while (sz != 0) {
        read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if (mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
            return KERN_FAILURE;
        }
        p += read_sz;
        sz -= read_sz;
        addr += read_sz;
    }
    return KERN_SUCCESS;
}

static kern_return_t kwrite_buf_tfp0(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
    vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_msg_type_number_t write_sz;

    while (sz != 0) {
        write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if (mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
            return KERN_FAILURE;
        }
        p += write_sz;
        sz -= write_sz;
        addr += write_sz;
    }
    return KERN_SUCCESS;
}

static kaddr_t get_kbase(kaddr_t *kslide) {
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    vm_region_extended_info_data_t extended_info;
    task_dyld_info_data_t dyld_info;
    kaddr_t addr, rtclock_datap;
    struct mach_header_64 mh64;
    mach_port_t obj_nm;
    mach_vm_size_t sz;

    if (task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS && dyld_info.all_image_info_size != 0) {
        *kslide = dyld_info.all_image_info_size;
        return VM_KERNEL_LINK_ADDRESS + *kslide;
    }
    cnt = VM_REGION_EXTENDED_INFO_COUNT;
    for (addr = 0; mach_vm_region(tfp0, &addr, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&extended_info, &cnt, &obj_nm) == KERN_SUCCESS; addr += sz) {
        mach_port_deallocate(mach_task_self(), obj_nm);
        if (extended_info.user_tag == VM_KERN_MEMORY_CPU && extended_info.protection == VM_PROT_DEFAULT) {
            if (kread_buf_tfp0(addr + CPU_DATA_RTCLOCK_DATAP_OFF, &rtclock_datap, sizeof(rtclock_datap)) != KERN_SUCCESS) {
                break;
            }
            rtclock_datap = trunc_page_kernel(rtclock_datap);
            do {
                if (rtclock_datap <= VM_KERNEL_LINK_ADDRESS) {
                    return 0;
                }
                rtclock_datap -= vm_kernel_page_size;
                if (kread_buf_tfp0(rtclock_datap, &mh64, sizeof(mh64)) != KERN_SUCCESS) {
                    return 0;
                }
            } while (mh64.magic != MH_MAGIC_64 || mh64.cputype != CPU_TYPE_ARM64 || mh64.filetype != MH_EXECUTE);
            *kslide = rtclock_datap - VM_KERNEL_LINK_ADDRESS;
            return rtclock_datap;
        }
    }
    return 0;
}

static kern_return_t find_section(kaddr_t sg64_addr, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
    kaddr_t s64_addr, s64_end;

    for (s64_addr = sg64_addr + sizeof(sg64), s64_end = s64_addr + (sg64.cmdsize - sizeof(*sp)); s64_addr < s64_end; s64_addr += sizeof(*sp)) {
        if (kread_buf_tfp0(s64_addr, sp, sizeof(*sp)) != KERN_SUCCESS) {
            break;
        }
        if (strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
            return KERN_SUCCESS;
        }
    }
    return KERN_FAILURE;
}

static void sec_reset(sec_64_t *sec) {
    memset(&sec->s64, '\0', sizeof(sec->s64));
    sec->data = NULL;
}

static void sec_term(sec_64_t *sec) {
    free(sec->data);
    sec_reset(sec);
}

static kern_return_t sec_init(sec_64_t *sec) {
    if ((sec->data = malloc(sec->s64.size)) != NULL) {
        if (kread_buf_tfp0(sec->s64.addr, sec->data, sec->s64.size) == KERN_SUCCESS) {
            return KERN_SUCCESS;
        }
        sec_term(sec);
    }
    return KERN_FAILURE;
}

static void pfinder_reset(pfinder_t *pfinder) {
    sec_reset(&pfinder->sec_text);
    sec_reset(&pfinder->sec_cstring);
}

static void pfinder_term(pfinder_t *pfinder) {
    sec_term(&pfinder->sec_text);
    sec_term(&pfinder->sec_cstring);
    pfinder_reset(pfinder);
}

static kern_return_t pfinder_init(pfinder_t *pfinder, kaddr_t kbase) {
    kern_return_t ret = KERN_FAILURE;
    struct segment_command_64 sg64;
    kaddr_t sg64_addr, sg64_end;
    struct mach_header_64 mh64;
    struct section_64 s64;

    pfinder_reset(pfinder);
    if (kread_buf_tfp0(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
        for (sg64_addr = kbase + sizeof(mh64), sg64_end = sg64_addr + (mh64.sizeofcmds - sizeof(sg64)); sg64_addr < sg64_end; sg64_addr += sg64.cmdsize) {
            if (kread_buf_tfp0(sg64_addr, &sg64, sizeof(sg64)) != KERN_SUCCESS) {
                break;
            }
            if (sg64.cmd == LC_SEGMENT_64) {
                if (strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_TEXT, &s64) == KERN_SUCCESS) {
                    pfinder->sec_text.s64 = s64;
                } else if (strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_CSTRING, &s64) == KERN_SUCCESS) {
                    pfinder->sec_cstring.s64 = s64;
                }
            }
            if (pfinder->sec_text.s64.size != 0 && pfinder->sec_cstring.s64.size != 0) {
                if (sec_init(&pfinder->sec_text) == KERN_SUCCESS) {
                    ret = sec_init(&pfinder->sec_cstring);
                }
                break;
            }
        }
    }
    if (ret != KERN_SUCCESS) {
        pfinder_term(pfinder);
    }
    return ret;
}

static kaddr_t pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
    uint64_t x[32] = { 0 };
    uint32_t insn;

    for (; start >= pfinder.sec_text.s64.addr && start < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insn)); start += sizeof(insn)) {
        memcpy(&insn, pfinder.sec_text.data + (start - pfinder.sec_text.s64.addr), sizeof(insn));
        if (IS_LDR_X(insn)) {
            x[RD(insn)] = start + LDR_X_IMM(insn);
        } else if (IS_ADR(insn)) {
            x[RD(insn)] = start + ADR_IMM(insn);
        } else if (IS_ADRP(insn)) {
            x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
            continue;
        } else if (IS_ADD_X(insn)) {
            x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
        } else if (IS_LDR_X_UNSIGNED_IMM(insn)) {
            x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
        } else if (IS_RET(insn)) {
            memset(x, '\0', sizeof(x));
        }
        if (RD(insn) == rd) {
            if (to == 0) {
                return x[rd];
            }
            if (x[rd] == to) {
                return start;
            }
        }
    }
    return 0;
}

static kaddr_t pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
    const char *p, *e;
    size_t len;

    for (p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p < e; p += len) {
        len = strlen(p) + 1;
        if (strncmp(str, p, len) == 0) {
            return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
        }
    }
    return 0;
}

static kaddr_t pfinder_allproc(pfinder_t pfinder) {
    kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

    if (ref == 0) {
        ref = pfinder_xref_str(pfinder, "shutdownwait", 3);  /* msleep */
    }
    return pfinder_xref_rd(pfinder, 8, ref, 0);
}

// pfinder-style allproc scan for our own proc (plus007 find_task verbatim,
// returning the proc pointer).
static uint64_t find_our_proc(pid_t pid) {
    kaddr_t cur = allproc;
    pid_t cur_pid;

    while (kread_buf_tfp0(cur, &cur, sizeof(cur)) == KERN_SUCCESS && cur != 0) {
        if (kread_buf_tfp0(cur + off_p_pid, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
            return cur;
        }
    }
    return 0;
}

static int krw_init_tfp0(void) {
    kaddr_t kbase, kslide;
    pfinder_t pfinder;

    if (is_arm64e()) {
        // Spec: NEVER tfp0 on arm64e — PAC makes the allproc walk unsafe
        // without PPL primitives.
        shdw_log("tfp0: refused on arm64e");
        return 1;
    }
    if (init_tfp0() != KERN_SUCCESS) {
        return 1;
    }
    if ((kbase = get_kbase(&kslide)) == 0) {
        shdw_log("tfp0: get_kbase failed");
        return 1;
    }
    shdw_log("tfp0: kbase 0x%llx kslide 0x%llx", kbase, kslide);

    if (pfinder_init(&pfinder, kbase) != KERN_SUCCESS) {
        shdw_log("tfp0: pfinder_init failed");
        return 1;
    }
    if ((allproc = pfinder_allproc(pfinder)) == 0) {
        pfinder_term(&pfinder);
        shdw_log("tfp0: pfinder_allproc failed");
        return 1;
    }
    pfinder_term(&pfinder);

    gOurProc = find_our_proc(getpid());
    if (gOurProc == 0) {
        shdw_log("tfp0: find_our_proc failed");
        return 1;
    }
    shdw_log("tfp0: our proc 0x%llx", gOurProc);
    return 0;
}

// ---------------------------------------------------------------------------
// Unified krw dispatch — every call checks status; failures are never ignored
// ---------------------------------------------------------------------------

// Kernel-space pointer plausibility: nonzero, canonical, 8-aligned.
static bool kptr_plausible(uint64_t p) {
    if (p == 0) return false;
    if ((p & 0xFF00000000000000ULL) != 0xFF00000000000000ULL) return false;
    if ((p & 7) != 0) return false;
    return true;
}

// PAC-unsign a kernel pointer (kernel.m:91-103 verbatim).  Zero guard added
// (unsigning 0 would produce the kernel link region and pass plausibility).
static uint64_t unsign_kptr(uint64_t pac_kaddr) {
    if (t1sz_boot == 0) {
        return pac_kaddr;
    }
    if (pac_kaddr == 0) {
        return 0;
    }
    if ((pac_kaddr & 0xFFFFFF0000000000) == 0xFFFFFF0000000000) {
        return pac_kaddr;
    }
    if (t1sz_boot != 0) {
        return pac_kaddr |= ~((1ULL << (64U - t1sz_boot)) - 1U);
    }
    return pac_kaddr;
}

static bool krw_read(uint64_t addr, void *buf, size_t len) {
    if (gKrwMode == KRW_LIBJB) {
        return libjb_kreadbuf(addr, buf, len) == 0;
    }
    return kread_buf_tfp0(addr, buf, len) == KERN_SUCCESS;
}

static bool krw_write(uint64_t addr, const void *buf, size_t len) {
    if (gKrwMode == KRW_LIBJB) {
        return libjb_kwritebuf(addr, buf, len) == 0;
    }
    return kwrite_buf_tfp0(addr, buf, len) == KERN_SUCCESS;
}

static bool krw_read32(uint64_t addr, uint32_t *out) {
    return krw_read(addr, out, sizeof(*out));
}

static bool krw_read16(uint64_t addr, uint16_t *out) {
    return krw_read(addr, out, sizeof(*out));
}

static bool krw_write32(uint64_t addr, uint32_t val) {
    return krw_write(addr, &val, sizeof(val));
}

// Pointer read with PAC stripping.  Prefer libjailbreak's kread_ptr when
// available (spec); otherwise status-returning kreadbuf + t1sz unsign.
static bool krw_read_ptr(uint64_t addr, uint64_t *out) {
    uint64_t v = 0;
    if (gKrwMode == KRW_LIBJB && libjb_kread_ptr) {
        v = libjb_kread_ptr(addr);
        v = unsign_kptr(v);
    } else {
        if (!krw_read(addr, &v, sizeof(v))) return false;
        v = unsign_kptr(v);
    }
    if (!kptr_plausible(v)) return false;
    *out = v;
    return true;
}

// proc_find (libjb) / cached own proc (tfp0)
static uint64_t proc_find_self(void) {
    if (gKrwMode == KRW_LIBJB) {
        return libjb_proc_find(getpid());
    }
    return gOurProc;
}

static void proc_rele_self(uint64_t proc) {
    if (gKrwMode == KRW_LIBJB && libjb_proc_rele && proc != 0) {
        libjb_proc_rele(proc);
    }
}

// ---------------------------------------------------------------------------
// Vnode flag ops + validation
// ---------------------------------------------------------------------------

// Set/clear VISSHADOW and READ BACK to verify (spec: read back after writing).
static bool vnode_set_flag(uint64_t vnode, bool set) {
    uint32_t flags = 0;
    if (!krw_read32(vnode + OFF_VNODE_V_FLAGS, &flags)) {
        shdw_log("vnode_set_flag: read failed at 0x%llx", vnode);
        return false;
    }
    uint32_t nf = set ? (flags | VISSHADOW) : (flags & ~VISSHADOW);
    if (nf == flags) {
        return true;   // already in the desired state
    }
    if (!krw_write32(vnode + OFF_VNODE_V_FLAGS, nf)) {
        shdw_log("vnode_set_flag: write failed at 0x%llx", vnode);
        return false;
    }
    uint32_t check = 0;
    if (!krw_read32(vnode + OFF_VNODE_V_FLAGS, &check)) {
        shdw_log("vnode_set_flag: readback failed at 0x%llx", vnode);
        return false;
    }
    if (((check & VISSHADOW) != 0) != set) {
        shdw_log("vnode_set_flag: readback mismatch at 0x%llx (0x%x)", vnode, check);
        return false;
    }
    return true;
}

// Runtime validation of a resolved vnode (spec section 2): flag readable,
// usecount/iocount sane (we hold a retained fd, so usecount >= 1), vnode type
// plausible.  All reads — never writes.
static bool vnode_plausible(uint64_t vnode) {
    uint32_t flags = 0;
    if (!krw_read32(vnode + OFF_VNODE_V_FLAGS, &flags)) {
        shdw_log("vnode_plausible: flag read failed at 0x%llx", vnode);
        return false;
    }
    uint32_t usecount = 0, iocount = 0;
    if (!krw_read32(vnode + OFF_VNODE_V_USECOUNT, &usecount) ||
        !krw_read32(vnode + OFF_VNODE_V_IOCOUNT, &iocount)) {
        shdw_log("vnode_plausible: count read failed at 0x%llx", vnode);
        return false;
    }
    if (usecount == 0 || usecount > 0x1000000 || iocount > 0x1000000) {
        shdw_log("vnode_plausible: implausible counts (u=%u i=%u) at 0x%llx", usecount, iocount, vnode);
        return false;
    }
    uint16_t vtype = 0;
    if (!krw_read16(vnode + OFF_VNODE_V_TYPE, &vtype)) {
        shdw_log("vnode_plausible: type read failed at 0x%llx", vnode);
        return false;
    }
    if (vtype != VREG && vtype != VDIR && vtype != VLNK) {
        shdw_log("vnode_plausible: implausible type %u at 0x%llx", vtype, vnode);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// fd → vnode resolution (fd-walk of OUR OWN proc; retained-fd design)
// ---------------------------------------------------------------------------

static bool read_fd_entry(uint64_t filedesc, int fd, uint64_t *out) {
    // Re-read the fd-array entry; a mismatch means the table relocated —
    // the caller retries the whole walk.
    uint64_t a = 0, b = 0;
    if (gFdTableInline) {
        if (!krw_read(filedesc + 8 * fd, &a, sizeof(a))) return false;
        if (!krw_read(filedesc + 8 * fd, &b, sizeof(b))) return false;
    } else {
        uint64_t ofiles = 0;
        if (!krw_read_ptr(filedesc + off_fd_ofiles, &ofiles)) return false;
        if (!krw_read(ofiles + 8 * fd, &a, sizeof(a))) return false;
        if (!krw_read(ofiles + 8 * fd, &b, sizeof(b))) return false;
    }
    if (a != b) return false;   // relocated between reads
    if (!kptr_plausible(unsign_kptr(a))) return false;
    *out = unsign_kptr(a);
    return true;
}

// Walk: proc → p_fd → fd_ofiles[fd] → f_fglob → fg_data.  Validates every
// step (spec section 2).  The open fd is retained by the caller; this only
// resolves the vnode and captures v_id (if reachable).
static bool resolve_vnode_for_fd(int fd, uint64_t *outVnode, uint64_t *outVId) {
    uint64_t proc = proc_find_self();
    if (proc == 0) {
        shdw_log("resolve: proc_find failed");
        return false;
    }

    // proc PID must match the daemon pid (spec).
    uint32_t procPid = 0;
    if (!krw_read32(proc + off_p_pid, &procPid) || procPid != (uint32_t)getpid()) {
        shdw_log("resolve: proc pid mismatch (0x%x != %d) at 0x%llx", procPid, getpid(), proc);
        proc_rele_self(proc);
        return false;
    }

    uint64_t filedesc = 0;
    if (!krw_read_ptr(proc + off_p_pfd, &filedesc)) {
        shdw_log("resolve: p_pfd read failed");
        proc_rele_self(proc);
        return false;
    }

    // fd within table bounds: the entry itself is re-read and validated
    // (canonical, nonzero) — an out-of-bounds read yields garbage and is
    // rejected; our fd is in-bounds by construction (open() succeeded).
    for (int attempt = 0; attempt < 3; attempt++) {
        uint64_t openedfile = 0;
        if (!read_fd_entry(filedesc, fd, &openedfile)) {
            continue;   // table relocated — retry
        }
        uint64_t fileglob = 0;
        if (!krw_read_ptr(openedfile + off_fp_fglob, &fileglob)) {
            shdw_log("resolve: f_fglob read failed");
            break;
        }
        // fileglob->fg_ops->fo_type == DTYPE_VNODE (spec)
        uint64_t fg_ops = 0;
        if (!krw_read_ptr(fileglob + OFF_FG_OPS, &fg_ops)) {
            shdw_log("resolve: fg_ops read failed");
            break;
        }
        uint32_t fo_type = 0;
        if (!krw_read32(fg_ops + OFF_FO_TYPE, &fo_type)) {
            shdw_log("resolve: fo_type read failed");
            break;
        }
        if (fo_type != DTYPE_VNODE) {
            shdw_log("resolve: fd %d is not a vnode (fo_type %u)", fd, fo_type);
            break;
        }
        uint64_t vnode = 0;
        if (!krw_read_ptr(fileglob + off_fg_data, &vnode)) {
            shdw_log("resolve: fg_data read failed");
            break;
        }
        if (!vnode_plausible(vnode)) {
            shdw_log("resolve: vnode validation failed at 0x%llx", vnode);
            break;
        }
        // Capture v_id if reachable (spec).
        uint64_t vId = 0;
        uint32_t vid32 = 0;
        if (krw_read32(vnode + OFF_VNODE_V_ID, &vid32)) {
            vId = vid32;
        }
        proc_rele_self(proc);
        *outVnode = vnode;
        *outVId = vId;
        return true;
    }
    proc_rele_self(proc);
    return false;
}

// ---------------------------------------------------------------------------
// Ledger (write-ahead, mayBeHidden semantics; single serial writer)
// ---------------------------------------------------------------------------
//
// Record line:  <state>|<path>|<ownerKey>|<vnodeHex>|<vIdHex>
//   state: 0 = mayBeHidden, 1 = hidden.
// File:     SHADOWLEDGER1\n<bootUUID>\n<record>...
// Durability: write tmp → fsync → rename → fsync dir.
// A recorded entry means "this operation MAY have happened", never "safe to
// skip".  Per-owner records for a path are removed only at successful
// teardown (WAL-conservative: a crash in any release window re-adopts the
// resource and the client re-releases).

static NSString *gBootUUID = nil;   // current boot session (ledger key)

static NSString *ledger_dir(void) {
    static NSString *dir = nil;
    if (!dir) {
        dir = gIsRootless
            ? @"/var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd"
            : @"/var/mobile/Library/Preferences/me.jjolano.shadowd";
    }
    return dir;
}

static NSString *ledger_file_path(void) {
    return [ledger_dir() stringByAppendingPathComponent:@"shadowd.ledger"];
}

static bool fsync_dir(NSString *dir) {
    int dfd = open(dir.UTF8String, O_RDONLY);
    if (dfd < 0) return false;
    bool ok = (fsync(dfd) == 0);
    close(dfd);
    return ok;
}

static bool ledger_write_lines(NSString *bootUUID, NSArray<NSString *> *records) {
    NSMutableString *contents = [NSMutableString stringWithString:@"SHADOWLEDGER1\n"];
    if (bootUUID) [contents appendString:bootUUID];
    [contents appendString:@"\n"];
    for (NSString *rec in records) {
        [contents appendString:rec];
        [contents appendString:@"\n"];
    }

    NSString *dir = ledger_dir();
    if (![[NSFileManager defaultManager] fileExistsAtPath:dir]) {
        if (![[NSFileManager defaultManager] createDirectoryAtPath:dir
                                       withIntermediateDirectories:YES
                                                        attributes:@{NSFilePosixPermissions: @0700}
                                                             error:nil]) {
            shdw_log("ledger: failed to create dir %s", dir.UTF8String);
            return false;
        }
    }
    NSString *path = ledger_file_path();
    NSString *tmp = [path stringByAppendingString:@".tmp"];

    int fd = open(tmp.UTF8String, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        shdw_log("ledger: open tmp failed (%s)", strerror(errno));
        return false;
    }
    fchmod(fd, 0600);
    const char *bytes = contents.UTF8String;
    size_t len = strlen(bytes);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, bytes + off, len - off);
        if (n <= 0) {
            close(fd);
            unlink(tmp.UTF8String);
            shdw_log("ledger: write failed (%s)", strerror(errno));
            return false;
        }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp.UTF8String);
        shdw_log("ledger: fsync failed");
        return false;
    }
    close(fd);
    if (rename(tmp.UTF8String, path.UTF8String) != 0) {
        unlink(tmp.UTF8String);
        shdw_log("ledger: rename failed (%s)", strerror(errno));
        return false;
    }
    fsync_dir(dir);
    return true;
}

static NSArray<NSString *> *ledger_read(NSString **outBootUUID) {
    NSString *path = ledger_file_path();
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return @[];
    }
    NSError *err = nil;
    NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&err];
    if (!contents) {
        shdw_log("ledger: unreadable (%s), treating as empty", err.localizedDescription.UTF8String);
        return @[];
    }
    NSArray<NSString *> *lines = [contents componentsSeparatedByString:@"\n"];
    NSMutableArray<NSString *> *records = [NSMutableArray array];
    NSString *boot = nil;
    for (NSUInteger i = 0; i < lines.count; i++) {
        NSString *line = lines[i];
        if (line.length == 0) continue;
        if (i == 0) continue;          // header
        if (i == 1) { boot = line; continue; }
        [records addObject:line];
    }
    if (outBootUUID) *outBootUUID = boot;
    return records;
}

static void ledger_wipe(void) {
    NSString *path = ledger_file_path();
    if (unlink(path.UTF8String) == 0) {
        fsync_dir(ledger_dir());
    }
}

static bool ledger_add_record(const char *path, const char *ownerKey, uint64_t vnode, uint64_t vId, int state) {
    NSString *boot = nil;
    NSMutableArray<NSString *> *records = [NSMutableArray arrayWithArray:ledger_read(&boot)];
    if (!boot) boot = gBootUUID;
    [records addObject:[NSString stringWithFormat:@"%d|%s|%s|0x%llx|0x%llx", state, path, ownerKey, vnode, vId]];
    return ledger_write_lines(boot, records);
}

static bool ledger_update_record(const char *path, const char *ownerKey, uint64_t vnode, uint64_t vId, int state) {
    NSString *boot = nil;
    NSMutableArray<NSString *> *records = [NSMutableArray arrayWithArray:ledger_read(&boot)];
    if (!boot) boot = gBootUUID;
    NSString *replacement = [NSString stringWithFormat:@"%d|%s|%s|0x%llx|0x%llx", state, path, ownerKey, vnode, vId];
    NSString *prefix = [NSString stringWithFormat:@"|%s|%s|", path, ownerKey];
    BOOL found = NO;
    for (NSUInteger i = 0; i < records.count; i++) {
        if ([records[i] rangeOfString:prefix].location != NSNotFound) {
            records[i] = replacement;
            found = YES;
            break;
        }
    }
    if (!found) [records addObject:replacement];
    return ledger_write_lines(boot, records);
}

static bool ledger_remove_path_records(const char *path) {
    NSString *boot = nil;
    NSMutableArray<NSString *> *records = [NSMutableArray arrayWithArray:ledger_read(&boot)];
    if (!boot) boot = gBootUUID;
    NSString *marker = [NSString stringWithFormat:@"|%s|", path];
    NSMutableArray<NSString *> *kept = [NSMutableArray array];
    for (NSString *rec in records) {
        if ([rec rangeOfString:marker].location == NSNotFound) {
            [kept addObject:rec];
        }
    }
    if (kept.count == records.count) return true;   // nothing to remove
    if (kept.count == 0) {
        ledger_wipe();
        return true;
    }
    return ledger_write_lines(boot, kept);
}

// ---------------------------------------------------------------------------
// Boot UUID (ledger key)
// ---------------------------------------------------------------------------

static bool get_boot_uuid(char *buf, size_t len) {
    size_t size = len;
    if (sysctlbyname("kern.bootsessionuuid", buf, &size, NULL, 0) != 0) {
        return false;
    }
    buf[size] = '\0';
    // Format is "UUID: <uuid>"
    if (strncmp(buf, "UUID: ", 6) == 0) {
        memmove(buf, buf + 6, strlen(buf + 6) + 1);
    }
    return buf[0] != '\0';
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

@interface ShadowResource : NSObject
@property (nonatomic) int fd;                    // retained fd (>= 0), -1 = restart-adopted
@property (nonatomic) uint64_t vnode;            // resolved vnode
@property (nonatomic) uint64_t vId;              // captured v_id (identity check)
@property (nonatomic) BOOL flagSet;              // VISSHADOW currently set
@property (nonatomic, strong) NSMutableSet<NSString *> *owners;  // owner keys
@end

@implementation ShadowResource
@end

// All resource/ledger/kernel activity: ONE serial queue (spec: single serial
// daemon writer).
static dispatch_queue_t gKernelQueue;

static NSMutableDictionary<NSString *, ShadowResource *> *gResources;
static NSMutableSet<NSString *> *gPendingReleases;   // release retries

// May we write to this vnode?  A retained fd pins the vnode — always safe.
// A restart-adopted resource (fd == -1, path was already hidden when we came
// up) has no fresh anchor: re-verify vnode identity (v_id) before ANY write
// — never write through a stale saved address blindly (spec).
static bool vnode_writeable(ShadowResource *res) {
    if (res.fd >= 0) {
        return true;
    }
    if (res.vId == 0) {
        shdw_log("vnode_writeable: no identity recorded for 0x%llx — refusing write", res.vnode);
        return false;
    }
    uint32_t vid = 0;
    if (!krw_read32(res.vnode + OFF_VNODE_V_ID, &vid) || vid != (uint32_t)res.vId) {
        shdw_log("vnode_writeable: identity mismatch at 0x%llx (0x%x != 0x%llx) — refusing write",
                 res.vnode, vid, res.vId);
        return false;
    }
    return true;
}

// Teardown a resource: clear VISSHADOW (fd held), verify, close fd, THEN
// durably remove the ledger record.  Returns false if the clear failed — the
// caller retains fd + record and retries later.
static bool resource_teardown(ShadowResource *res, NSString *path) {
    if (res.flagSet) {
        if (!vnode_writeable(res)) {
            shdw_log("teardown %s: vnode not writeable — retaining fd + record", path.UTF8String);
            return false;
        }
        if (!vnode_set_flag(res.vnode, false)) {
            shdw_log("teardown %s: clear VISSHADOW failed — retaining fd + record", path.UTF8String);
            return false;
        }
        res.flagSet = NO;
    }
    if (res.fd >= 0) {
        close(res.fd);
        res.fd = -1;
    }
    ledger_remove_path_records(path.UTF8String);
    [gResources removeObjectForKey:path];
    shdw_log("released: %s", path.UTF8String);
    return true;
}

// Remove one owner everywhere; tear down resources with no owners left.
static void owner_gone(NSString *ownerKey) {
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

// Polling fallback owner-death detection: kill(pid, 0) + start-time check
// (survives PID reuse).  Also retries pending releases.
static void sweep_owners(void) {
    for (NSString *path in [gResources allKeys]) {
        ShadowResource *res = gResources[path];
        NSMutableSet<NSString *> *dead = [NSMutableSet set];
        for (NSString *ownerKey in res.owners) {
            pid_t pid; uint64_t sec, usec;
            parse_owner_key(ownerKey, &pid, &sec, &usec);
            if (pid <= 0) { [dead addObject:ownerKey]; continue; }
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
            if (!alive) {
                shdw_log("sweep: owner %s dead", ownerKey.UTF8String);
                [dead addObject:ownerKey];
            }
        }
        for (NSString *k in dead) {
            [res.owners removeObject:k];
        }
        if (res.owners.count == 0 && res.flagSet) {
            if (!resource_teardown(res, path)) {
                [gPendingReleases addObject:path];
            }
        }
    }
    for (NSString *path in [gPendingReleases copy]) {
        ShadowResource *res = gResources[path];
        if (!res || res.owners.count > 0 || !res.flagSet) {
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

static bool allowlisted(const char *path) {
    for (NSUInteger i = 0; i < kAllowlistCount; i++) {
        if (strcmp(kAllowlist[i].UTF8String, path) == 0) return true;
    }
    return false;
}

// Wait for krw init to resolve (bounded).  Returns ENOTSUP when disabled.
static uint32_t acquire_status_if_ready(void) {
    if (gKrwState == KRW_INIT) {
        dispatch_semaphore_wait(gKrwReadySem,
                                dispatch_time(DISPATCH_TIME_NOW, 35 * NSEC_PER_SEC));
    }
    if (gKrwState != KRW_READY) {
        return SHADOWD_STATUS_ENOTSUP;
    }
    return SHADOWD_STATUS_OK;
}

// Hide every allowlisted path for one owner.  Dedup by resource: a second
// acquire of an already-hidden path only adds the owner — it does NOT
// reopen/rehide (spec).
static uint32_t acquire_for_owner(NSString *ownerKey) {
    uint32_t gated = acquire_status_if_ready();
    if (gated != SHADOWD_STATUS_OK) return gated;

    uint32_t status = SHADOWD_STATUS_OK;
    for (NSUInteger i = 0; i < kAllowlistCount; i++) {
        NSString *path = kAllowlist[i];
        ShadowResource *res = gResources[path];
        if (res) {
            if (![res.owners containsObject:ownerKey]) {
                [res.owners addObject:ownerKey];
                // Durable per-owner record so a crash keeps owner identity.
                ledger_add_record(path.UTF8String, ownerKey.UTF8String, res.vnode, res.vId, 1 /*hidden*/);
                shdw_log("acquire %s: added owner %s", path.UTF8String, ownerKey.UTF8String);
            }
            continue;
        }

        int fd = open(path.UTF8String, O_RDONLY);
        if (fd < 0) {
            shdw_log("acquire %s: skip (open failed: %s)", path.UTF8String, strerror(errno));
            continue;   // path doesn't exist (yet) — not an error
        }

        // WAL: resolve the vnode, then durably persist the mayBeHidden record
        // BEFORE the kernel write.
        uint64_t vnode = 0, vId = 0;
        if (!resolve_vnode_for_fd(fd, &vnode, &vId)) {
            shdw_log("acquire %s: vnode resolution failed", path.UTF8String);
            close(fd);
            status = SHADOWD_STATUS_EBUSY;
            continue;
        }
        if (!ledger_add_record(path.UTF8String, ownerKey.UTF8String, vnode, vId, 0 /*mayBeHidden*/)) {
            shdw_log("acquire %s: ledger write failed", path.UTF8String);
            close(fd);
            status = SHADOWD_STATUS_EBUSY;
            continue;
        }

        // Set VISSHADOW and verify by reread.
        if (!vnode_set_flag(vnode, true)) {
            shdw_log("acquire %s: hide failed at 0x%llx", path.UTF8String, vnode);
            ledger_remove_path_records(path.UTF8String);   // roll back record
            close(fd);
            status = SHADOWD_STATUS_EBUSY;
            continue;
        }

        // Mark the record durably hidden.
        if (!ledger_update_record(path.UTF8String, ownerKey.UTF8String, vnode, vId, 1 /*hidden*/)) {
            shdw_log("acquire %s: ledger state update failed (record stays mayBeHidden; recovery reconciles)", path.UTF8String);
        }

        ShadowResource *nr = [ShadowResource new];
        nr.fd = fd;
        nr.vnode = vnode;
        nr.vId = vId;
        nr.flagSet = YES;
        nr.owners = [NSMutableSet setWithObject:ownerKey];
        gResources[path] = nr;
        shdw_log("hidden: %s (vnode 0x%llx v_id %llu)", path.UTF8String, vnode, vId);
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

static void recover_from_ledger(void) {
    NSString *boot = nil;
    NSArray<NSString *> *records = ledger_read(&boot);

    if (records.count == 0) {
        return;
    }
    if (!boot || ![boot isEqualToString:gBootUUID]) {
        // Fresh kernel — vnodes were destroyed by the reboot.  Discard all
        // records WITHOUT any kernel writes (spec).
        shdw_log("ledger: boot session mismatch — discarding %lu records without kernel writes", (unsigned long)records.count);
        ledger_wipe();
        return;
    }
    shdw_log("ledger: boot session matches — reconciling %lu records", (unsigned long)records.count);

    NSMutableArray<NSString *> *kept = [NSMutableArray array];
    for (NSString *rec in records) {
        NSArray<NSString *> *f = [rec componentsSeparatedByString:@"|"];
        if (f.count != 5) {
            shdw_log("ledger: malformed record dropped: %s", rec.UTF8String);
            continue;
        }
        int state = [f[0] intValue];
        NSString *path = f[1];
        NSString *ownerKey = f[2];
        uint64_t savedVnode = 0, savedVId = 0;
        sscanf(f[3].UTF8String, "0x%llx", &savedVnode);
        sscanf(f[4].UTF8String, "0x%llx", &savedVId);

        if (!allowlisted(path.UTF8String)) {
            shdw_log("ledger: non-allowlisted path dropped: %s", path.UTF8String);
            continue;
        }
        if (savedVnode == 0) {
            shdw_log("ledger: zero vnode dropped: %s", path.UTF8String);
            continue;
        }

        ShadowResource *res = gResources[path];
        if (res) {
            [res.owners addObject:ownerKey];
            [kept addObject:rec];
            continue;
        }

        int fd = open(path.UTF8String, O_RDONLY);
        if (fd >= 0) {
            // Path currently VISIBLE.
            if (state == 0 /*mayBeHidden*/) {
                // Positive evidence the kernel write never happened (a set
                // flag would make open fail with ENOENT) → the client never
                // got a success reply → safe to roll back; it will retry.
                shdw_log("ledger: mayBeHidden + visible → rolled back: %s", path.UTF8String);
                close(fd);
                continue;
            }
            // Record says hidden but the file opens: re-resolve the vnode
            // from the FRESH fd, never trust the saved vnodeAddr.
            uint64_t vnode = 0, vId = 0;
            if (!resolve_vnode_for_fd(fd, &vnode, &vId)) {
                shdw_log("ledger: re-resolve failed for %s", path.UTF8String);
                close(fd);
                [kept addObject:rec];   // keep for a future retry
                continue;
            }
            if (!vnode_set_flag(vnode, true)) {
                shdw_log("ledger: re-hide failed for %s", path.UTF8String);
                close(fd);
                [kept addObject:rec];
                continue;
            }
            ShadowResource *nr = [ShadowResource new];
            nr.fd = fd;
            nr.vnode = vnode;
            nr.vId = vId;
            nr.flagSet = YES;
            nr.owners = [NSMutableSet setWithObject:ownerKey];
            gResources[path] = nr;
            // Fix up the record with the fresh vnode identity.
            [kept addObject:[NSString stringWithFormat:@"1|%@|%@|0x%llx|0x%llx", path, ownerKey, vnode, vId]];
            shdw_log("ledger: re-hidden %s via fresh fd (vnode 0x%llx)", path.UTF8String, vnode);
        } else {
            // open failed (ENOENT): the file is genuinely hidden (vnode
            // still flagged) — or it was deleted.  Verify the saved vnode
            // READ-ONLY (flag set + v_id identity) before adopting.
            uint32_t flags = 0, vid = 0;
            if (!krw_read32(savedVnode + OFF_VNODE_V_FLAGS, &flags) || (flags & VISSHADOW) == 0) {
                shdw_log("ledger: saved vnode 0x%llx not flagged — dropped: %s", savedVnode, path.UTF8String);
                continue;
            }
            if (savedVId != 0 &&
                (!krw_read32(savedVnode + OFF_VNODE_V_ID, &vid) || vid != (uint32_t)savedVId)) {
                shdw_log("ledger: saved vnode 0x%llx identity mismatch — dropped: %s", savedVnode, path.UTF8String);
                continue;
            }
            ShadowResource *nr = [ShadowResource new];
            nr.fd = -1;   // no fd obtainable while hidden — anchor is the
                          // identity-verified saved vnode
            nr.vnode = savedVnode;
            nr.vId = savedVId;
            nr.flagSet = YES;
            nr.owners = [NSMutableSet setWithObject:ownerKey];
            gResources[path] = nr;
            [kept addObject:rec];
            shdw_log("ledger: adopted hidden %s (vnode 0x%llx, fd unavailable)", path.UTF8String, savedVnode);
        }
    }

    if (kept.count == 0) {
        ledger_wipe();
    } else {
        ledger_write_lines(gBootUUID, kept);
    }
}

// ---------------------------------------------------------------------------
// IPC server (Mach, synchronous)
// ---------------------------------------------------------------------------

static mach_port_t gServerPort = MACH_PORT_NULL;
static dispatch_queue_t gServerQueue;
static mach_port_t gNotifyPort = MACH_PORT_NULL;
static NSMutableDictionary<NSNumber *, NSString *> *gLeases;   // reply port → owner key

// Keep a send right to the client's reply port as the lease; install a
// dead-name notification; on the client's death the kernel notifies us and
// the owner's leases are released.
static void install_lease(mach_port_name_t replyPort, NSString *ownerKey) {
    mach_port_name_t previous = MACH_PORT_NULL;
    kern_return_t kr = mach_port_request_notification(mach_task_self(), replyPort,
                                                      MACH_NOTIFY_DEAD_NAME, 0,
                                                      gNotifyPort, MACH_MSG_TYPE_MAKE_SEND_ONCE,
                                                      &previous);
    if (kr != KERN_SUCCESS) {
        // The lease is already dead (client gone before we could arm the
        // notification) — treat the owner as dead.
        shdw_log("lease: dead-name request failed (0x%x) for owner %s", kr, ownerKey.UTF8String);
        dispatch_async(gKernelQueue, ^{
            owner_gone(ownerKey);
        });
        return;
    }
    gLeases[@(replyPort)] = ownerKey;
    shdw_log("lease: installed for owner %s (reply port 0x%x)", ownerKey.UTF8String, replyPort);
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

    kern_return_t kr = mach_msg(&reply.header, MACH_SEND_MSG, reply.header.msgh_size,
                                0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        shdw_log("reply: mach_msg failed (0x%x)", kr);
    }
}

static void handle_request(shadowd_request_t *req) {
    if (req->magic != SHADOWD_MAGIC) {
        shdw_log("request: bad magic 0x%x", req->magic);
        return;
    }
    if (req->version != SHADOWD_VERSION) {
        shdw_log("request: unsupported version %u", req->version);
        send_reply(req, SHADOWD_STATUS_ENOTSUP);
        return;
    }
    if (req->op == SHADOWD_OP_PING) {
        send_reply(req, SHADOWD_STATUS_OK);
        mach_port_deallocate(mach_task_self(), req->replyPort.name);
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
        send_reply(req, SHADOWD_STATUS_EPERM);
        return;
    }

    uint64_t sec = 0, usec = 0;
    if (!owner_start_time(pid, &sec, &usec)) {
        shdw_log("request: owner start time unavailable for pid %d (identity weakened)", pid);
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
        send_reply(req, status);
        mach_port_deallocate(mach_task_self(), req->replyPort.name);
        return;
    }
    shdw_log("request: unknown op %u", req->op);
    send_reply(req, SHADOWD_STATUS_ENOTSUP);
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
    if (req->header.msgh_size < sizeof(mach_msg_base_t)) {
        return;
    }
    handle_request(req);
}

static void setup_ipc_server(void) {
    gServerQueue = dispatch_queue_create("me.jjolano.shadowd.server", NULL);
    gLeases = [NSMutableDictionary dictionary];

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
        NSString *ownerKey = gLeases[@(deadName)];
        if (!ownerKey) {
            shdw_log("dead-name: unknown port 0x%x", deadName);
            return;
        }
        [gLeases removeObjectForKey:@(deadName)];
        shdw_log("dead-name: lease for owner %s died", ownerKey.UTF8String);
        dispatch_async(gKernelQueue, ^{
            owner_gone(ownerKey);
        });
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

static void shutdown_daemon(void) {
    shdw_log("shutdown: clearing all VISSHADOW flags");
    for (NSString *path in [gResources allKeys]) {
        ShadowResource *res = gResources[path];
        if (res.flagSet) {
            // Same identity rule as release: never write through a stale
            // saved address blindly (applies to restart-adopted resources).
            if (vnode_writeable(res) && vnode_set_flag(res.vnode, false)) {
                res.flagSet = NO;
                shdw_log("shutdown: cleared %s", path.UTF8String);
            } else {
                shdw_log("shutdown: FAILED to clear %s — flag may remain set", path.UTF8String);
            }
        }
        if (res.fd >= 0) {
            close(res.fd);
        }
    }
    ledger_wipe();
    shdw_log("shadowd exiting");
    exit(0);
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
            gKrwState = KRW_DISABLED;
            dispatch_semaphore_signal(gKrwReadySem);
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
            shdw_log("krw: arm64 — tfp0 path (A8-A11)");
            if (krw_init_tfp0() == 0) {
                gKrwMode = KRW_TFP0;
                ok = true;
            } else {
                shdw_log("krw: tfp0 init failed — feature disabled");
            }
        }

        if (ok) {
            gKrwState = KRW_READY;
            shdw_log("krw: ready (mode %s)", gKrwMode == KRW_LIBJB ? "libjailbreak" : "tfp0");
            // Recovery and acquires both run on the SAME serial kernel queue,
            // so enqueue recovery first and it will run before any later
            // acquire.  Signal the gate semaphore BEFORE enqueueing: an
            // acquire may already be blocked on it while occupying the
            // kernel queue — dispatch_sync from here would deadlock.
            dispatch_async(gKernelQueue, ^{
                recover_from_ledger();
            });
        } else {
            gKrwState = KRW_DISABLED;
        }
        dispatch_semaphore_signal(gKrwReadySem);
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
        gKrwReadySem = dispatch_semaphore_create(0);

        if (!version_gate()) {
            // Hard ceiling: feature disabled for this run; the daemon stays
            // alive but idles (IPC still answers ENOTSUP).
            gKrwState = KRW_DISABLED;
            dispatch_semaphore_signal(gKrwReadySem);
        } else {
            char uuid[128] = {0};
            if (!get_boot_uuid(uuid, sizeof(uuid))) {
                // Spec: boot UUID unavailable/empty → disable the feature.
                shdw_log("kern.bootsessionuuid unavailable — feature disabled");
                gKrwState = KRW_DISABLED;
                dispatch_semaphore_signal(gKrwReadySem);
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
