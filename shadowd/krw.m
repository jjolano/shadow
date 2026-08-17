//
//  krw.m
//  shadowd
//
//  Kernel read/write backends + vnode ops (extracted VERBATIM from main.m,
//  A6): libjb + tfp0/pfinder backends, the unified krw dispatch, vnode flag
//  ops/validation and fd→vnode resolution.  No behavior changes.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/vm_page_size.h>
#import <mach/vm_region.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <errno.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>

#include "krw.h"

// fileglob/fileops offsets (review-corrected): struct fileglob has f_ops at
// 0x28 (0x30 is fg_offset) and f_data at 0x38; struct fileops has fo_type as
// its FIRST member (offset 0x0).  DTYPE_VNODE == 1.
#define OFF_FG_OPS     0x28
#define OFF_FO_TYPE    0x0
#define DTYPE_VNODE    1

// Vnode types (vnode.h)
#define VNON 0
#define VREG 1
#define VDIR 2
#define VLNK 5    // 10 is VCPLX, not VLNK

// ---------------------------------------------------------------------------
// Offsets (corrected table — implement exactly as specified)
// ---------------------------------------------------------------------------

static uint32_t off_p_pid = 0;
static uint32_t off_p_pfd = 0;
static uint32_t off_fp_fglob = 0;
static uint32_t off_fg_data = 0;
static unsigned long long t1sz_boot = 0;
bool resolve_vnode_for_fd(int fd, uint64_t *outVnode, uint64_t *outVId);

bool is_arm64e(void) {
    // A27: FAIL CLOSED — initialize to a known non-arm64e value and CHECK the
    // sysctl result; on sysctl FAILURE treat the device as arm64e (never
    // "not arm64e").  Misclassifying an arm64e device as arm64 would select
    // the PAC-unsafe tfp0 backend on arm64e.
    cpu_subtype_t subtype = 0;
    size_t cpusz = sizeof(cpu_subtype_t);
    if (sysctlbyname("hw.cpusubtype", &subtype, &cpusz, NULL, 0) != 0) {
        shdw_log("is_arm64e: hw.cpusubtype failed — FAIL CLOSED, assuming arm64e (tfp0 refused)");
        return true;
    }
    return (subtype == 2 /* CPU_SUBTYPE_ARM64E */);
}

// t1sz_boot + tentative row dispatch — hard table replaced by runtime discovery.
// offset_init only assigns tentative values; krw_resolve_offsets() validates via
// probe fd → proc_find/gOurProc → kread+resolve, else brute-force scan.
int offset_init(void) {
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

    // Tentative assignment — table-driven Darwin→iOS, validated later.
    if (gDarwinMajor == 22) {
        shdw_log("offsets: tentative iOS 16 (p_pid 0x60, p_pfd 0xf8)");
        off_p_pid = 0x60; off_p_pfd = 0xf8; off_fp_fglob = 0x10; off_fg_data = 0x38;
        return 0;
    }
    if (gDarwinMajor >= 23) {
        // iOS 17-20 and future: same layout tentatively, resolved at runtime
        int ios = gDarwinMajor - 6;
        if (gDarwinMajor > 26) ios = gDarwinMajor - 6;
        shdw_log("offsets: tentative Darwin %d (iOS %d) p_pid 0x60, p_pfd 0xf8 — runtime resolve will decide", gDarwinMajor, ios);
        off_p_pid = 0x60; off_p_pfd = 0xf8; off_fp_fglob = 0x10; off_fg_data = 0x38;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_2) {
        shdw_log("offsets: tentative iOS 15.2+ (p_pid 0x68, p_pfd 0xf8)");
        off_p_pid = 0x68; off_p_pfd = 0xf8; off_fp_fglob = 0x10; off_fg_data = 0x38;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_0) {
        shdw_log("offsets: tentative iOS 15.0-15.1.1 (p_pid 0x68, p_pfd 0x100)");
        off_p_pid = 0x68; off_p_pfd = 0x100; off_fp_fglob = 0x10; off_fg_data = 0x38;
        return 0;
    }
    // Low bound (<15) still handled, but version_gate already fails closed.
    // Keep tentative for completeness — validation will still run if reached.
    shdw_log("offsets: tentative fallback (CF %.3f) p_pid 0x68, p_pfd 0xf8", kCFCoreFoundationVersionNumber);
    off_p_pid = 0x68; off_p_pfd = 0xf8; off_fp_fglob = 0x10; off_fg_data = 0x38;
    return 0;
}

// ponytail: brute-force window is small (pid 5 * pfd 7 * 2*3 = 210 tries, one kread+resolve each)
int krw_resolve_offsets(void) {
#ifdef SHADOW_TEST_HARNESS
    return 0;
#else
    // Probe with a REGULAR file: vnode_plausible accepts only VREG/VDIR/VLNK,
    // and /dev/null is VCHR — the tentative offsets would always "fail" here.
    int fd = open("/System/Library/CoreServices/SystemVersion.plist", O_RDONLY);
    if (fd < 0) fd = open("/", O_RDONLY);
    if (fd < 0) {
        shdw_log("krw_resolve_offsets: probe open failed (%s) — FAIL CLOSED", strerror(errno));
        return -1;
    }
    uint64_t vnode = 0, vId = 0;
    if (resolve_vnode_for_fd(fd, &vnode, &vId)) {
        shdw_log("krw_resolve_offsets: tentative validated (p_pid 0x%x p_pfd 0x%x fglob 0x%x fg_data 0x%x)", off_p_pid, off_p_pfd, off_fp_fglob, off_fg_data);
        close(fd);
        return 0;
    }
    shdw_log("krw_resolve_offsets: tentative failed — brute-force scanning");

    uint32_t orig_pid = off_p_pid, orig_pfd = off_p_pfd, orig_fglob = off_fp_fglob, orig_gd = off_fg_data;
    static const uint32_t pid_cands[] = {0x60, 0x68, 0x70, 0x58, 0x78};
    static const uint32_t pfd_cands[] = {0xf8, 0x100, 0xf0, 0xe8, 0x108, 0x110, 0xe0};
    static const uint32_t fg_cands[] = {0x10, 0x08};
    static const uint32_t gd_cands[] = {0x38, 0x30, 0x40};
    for (size_t i = 0; i < sizeof(pid_cands)/sizeof(pid_cands[0]); i++) {
        for (size_t j = 0; j < sizeof(pfd_cands)/sizeof(pfd_cands[0]); j++) {
            for (size_t k = 0; k < sizeof(fg_cands)/sizeof(fg_cands[0]); k++) {
                for (size_t l = 0; l < sizeof(gd_cands)/sizeof(gd_cands[0]); l++) {
                    off_p_pid = pid_cands[i];
                    off_p_pfd = pfd_cands[j];
                    off_fp_fglob = fg_cands[k];
                    off_fg_data = gd_cands[l];
                    // skip the already-tried tentative combo
                    if (off_p_pid == orig_pid && off_p_pfd == orig_pfd && off_fp_fglob == orig_fglob && off_fg_data == orig_gd) continue;
                    if (resolve_vnode_for_fd(fd, &vnode, &vId)) {
                        shdw_log("krw_resolve_offsets: discovered p_pid 0x%x p_pfd 0x%x fglob 0x%x fg_data 0x%x (vnode 0x%llx)", off_p_pid, off_p_pfd, off_fp_fglob, off_fg_data, vnode);
                        close(fd);
                        return 0;
                    }
                }
            }
        }
    }
    // restore tentative before failing closed (keeps logs coherent)
    off_p_pid = orig_pid; off_p_pfd = orig_pfd; off_fp_fglob = orig_fglob; off_fg_data = orig_gd;
    shdw_log("krw_resolve_offsets: all candidates failed — FAIL CLOSED");
    close(fd);
    return -1;
#endif
}

// ---------------------------------------------------------------------------
// KRW backends
// ---------------------------------------------------------------------------

krw_mode_t gKrwMode = KRW_NONE;
// NEW-3: gKrwState is written on the background init thread and read on the
// kernel queue — volatile is NOT synchronization.  Use C11 atomics.
_Atomic krw_state_t gKrwState = KRW_INIT;
static uint64_t gOurProc = 0;   // tfp0 path: cached own-proc from allproc scan

// ---- libjailbreak (Dopamine) ----
static void *gLibJB = NULL;
static int (*libjb_jbdInitPPLRW)(void) = NULL;
static int (*libjb_kreadbuf)(uint64_t, void *, size_t) = NULL;
static int (*libjb_kwritebuf)(uint64_t, const void *, size_t) = NULL;
static uint64_t (*libjb_proc_find)(pid_t) = NULL;
static int (*libjb_proc_rele)(uint64_t) = NULL;

// dlsym → typed function pointer without -Werror conversion issues.
#define DL_SYM(var, name) do { *(void **)(&(var)) = dlsym(gLibJB, (name)); } while (0)

// ---- libkrw (Siguza libkrw0, rootless standard) ----
static void *gLibKrw = NULL;
static int (*libkrw_kread)(uint64_t, void *, size_t) = NULL;
static int (*libkrw_kwrite)(void *, uint64_t, size_t) = NULL;

// One init attempt: dlopen + dlsym all symbols + jbdInitPPLRW.  Retried by
// the caller every 2s up to 30s.  The daemon is root, so no getuid hooking
// is needed (the jailed caller protection doesn't apply).
int krw_init_libjb_once(void) {
    if (!gLibJB) {
        gLibJB = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);
        if (!gLibJB) {
            shdw_log("libjailbreak: dlopen failed: %s", dlerror());
            return 1;
        }
    }
    DL_SYM(libjb_jbdInitPPLRW, "jbdInitPPLRW");
    DL_SYM(libjb_kreadbuf, "kreadbuf");
    DL_SYM(libjb_kwritebuf, "kwritebuf");
    DL_SYM(libjb_proc_find, "proc_find");
    DL_SYM(libjb_proc_rele, "proc_rele");

    if (!libjb_jbdInitPPLRW || !libjb_kreadbuf || !libjb_kwritebuf ||
        !libjb_proc_find) {
        shdw_log("libjailbreak: missing symbols (jbdInitPPLRW=%p kreadbuf=%p kwritebuf=%p proc_find=%p)",
                 libjb_jbdInitPPLRW, libjb_kreadbuf, libjb_kwritebuf,
                 libjb_proc_find);
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

// Presence probe for the arm64 branch: libjailbreak is installed only on
// Dopamine-family rootless builds (plain palera1n ships libkrw instead).
// Doubles as the first dlopen so a later krw_init_libjb_once reuses the
// handle.  A PRESENT-but-failing init is transient (jailbreakd still coming
// up) and worth retrying; an absent dylib must fall through to libkrw/tfp0
// without delay.
bool krw_libjb_present(void) {
    if (!gLibJB) {
        gLibJB = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);
        if (!gLibJB) {
            shdw_log("libjailbreak: dlopen failed: %s", dlerror());
            return false;
        }
    }
    return true;
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
    if (ret != KERN_SUCCESS) {
        mach_port_t host = mach_host_self();
        if (MACH_PORT_VALID(host)) {
            shdw_log("tfp0: host special port path (unc0ver-style)");
            ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
            mach_port_deallocate(mach_task_self(), host);
        }
    }
    // A26: verify the port is really the kernel task (pid 0) on BOTH paths —
    // the special-port path previously returned without checking.
    if (ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
        pid_t pid = -1;
        if (pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
            return ret;
        }
        shdw_log("tfp0: port is not the kernel task (pid %d) — rejecting", pid);
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

// Mode-aware kernel read for the pfinder/allproc machinery: routes through
// libkrw when that backend is active, tfp0 otherwise (libjb never runs
// pfinder).  libkrw signature: int kread(uint64_t from, void *to, size_t len).
// Chunked by page like the tfp0 path: libkrw's kread can fail on single
// multi-MB reads (pfinder reads whole kernel sections).
static bool kread_mode(kaddr_t addr, void *buf, size_t len) {
    if (gKrwMode == KRW_LIBKRW) {
        uint8_t *p = buf;
        while (len != 0) {
            size_t chunk = MIN(len, vm_kernel_page_size - (addr & vm_kernel_page_mask));
            if (libkrw_kread(addr, p, chunk) != 0) return false;
            p += chunk;
            addr += chunk;
            len -= chunk;
        }
        return true;
    }
    return kread_buf_tfp0(addr, buf, len) == KERN_SUCCESS;
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
        if (!kread_mode(s64_addr, sp, sizeof(*sp))) {
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
        if (kread_mode(sec->s64.addr, sec->data, sec->s64.size)) {
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
    if (kread_mode(kbase, &mh64, sizeof(mh64)) && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
        for (sg64_addr = kbase + sizeof(mh64), sg64_end = sg64_addr + (mh64.sizeofcmds - sizeof(sg64)); sg64_addr < sg64_end; sg64_addr += sg64.cmdsize) {
            if (!kread_mode(sg64_addr, &sg64, sizeof(sg64))) {
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

    // A section smaller than one instruction would underflow the loop bound
    // below and read past the malloc'd buffer.
    if (pfinder.sec_text.s64.size < sizeof(insn)) {
        return 0;
    }

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
        // Bound the scan: a section without a trailing NUL would make strlen
        // read past the malloc'd buffer.
        size_t avail = (size_t)(e - p);
        len = strnlen(p, avail);
        if (len == avail) {
            break;   // no NUL within the remaining buffer
        }
        len += 1;
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

    while (kread_mode(cur, &cur, sizeof(cur)) && cur != 0) {
        if (kread_mode(cur + off_p_pid, &cur_pid, sizeof(cur_pid)) && cur_pid == pid) {
            return cur;
        }
    }
    return 0;
}

int krw_init_tfp0(void) {
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

// libkrw (Siguza libkrw0, rootless standard).  The daemon is a LaunchDaemon
// (no entitlements), so kbase() is NOT used — it hangs without the proper
// signed entitlements on some builds; the mach header scan below is
// entitlement-free and validated on-device.
int krw_init_libkrw_once(void) {
    if (is_arm64e()) {
        // libkrw0's tfp0-style backend is not PAC-safe; never use on arm64e.
        shdw_log("libkrw: refused on arm64e");
        return 1;
    }
    if (!gLibKrw) {
        gLibKrw = dlopen("/var/jb/usr/lib/libkrw.0.dylib", RTLD_NOW);
        if (!gLibKrw) {
            shdw_log("libkrw: dlopen failed: %s", dlerror());
            return 1;
        }
    }
    *(void **)(&libkrw_kread) = dlsym(gLibKrw, "kread");
    *(void **)(&libkrw_kwrite) = dlsym(gLibKrw, "kwrite");
    if (!libkrw_kread || !libkrw_kwrite) {
        shdw_log("libkrw: missing symbols (kread=%p kwrite=%p)", libkrw_kread, libkrw_kwrite);
        return 1;
    }
    // NOTE: libkrw signature is kwrite(void *from, uint64_t to, size_t len)
    // — user buffer FIRST, kernel address SECOND (verified on-device).

    // kbase via mach header scan (kbase() hangs here).  Match only the
    // kernel mach-O: magic alone is not enough — the kernelcache image
    // contains kext headers (also 0xfeedfacf, MH_KEXT_BUNDLE) that can
    // appear earlier in the slide range.
    kaddr_t kbase = 0;
    for (uint64_t off = 0; off < 0x10000000ULL; off += 0x4000ULL) {
        struct mach_header_64 mh = {0};
        if (libkrw_kread(VM_KERNEL_LINK_ADDRESS + off, &mh, sizeof(mh)) != 0) continue;
        if (mh.magic == MH_MAGIC_64 && mh.filetype == MH_EXECUTE &&
            mh.cputype == CPU_TYPE_ARM64 && mh.ncmds > 5) {
            kbase = VM_KERNEL_LINK_ADDRESS + off;
            break;
        }
    }
    if (kbase == 0) {
        shdw_log("libkrw: mach header scan failed");
        return 1;
    }
    shdw_log("libkrw: kbase 0x%llx", kbase);

    // Route pfinder through libkrw before running it.
    krw_mode_t savedMode = gKrwMode;
    gKrwMode = KRW_LIBKRW;

    pfinder_t pfinder;
    if (pfinder_init(&pfinder, kbase) != KERN_SUCCESS) {
        gKrwMode = savedMode;
        shdw_log("libkrw: pfinder_init failed");
        return 1;
    }
    if ((allproc = pfinder_allproc(pfinder)) == 0) {
        pfinder_term(&pfinder);
        gKrwMode = savedMode;
        shdw_log("libkrw: pfinder_allproc failed");
        return 1;
    }
    pfinder_term(&pfinder);

    gOurProc = find_our_proc(getpid());
    if (gOurProc == 0) {
        gKrwMode = savedMode;
        shdw_log("libkrw: find_our_proc failed");
        return 1;
    }
    shdw_log("libkrw: our proc 0x%llx", gOurProc);
    return 0;
}

// ---------------------------------------------------------------------------
// Unified krw dispatch — every call checks status; failures are never ignored
// ---------------------------------------------------------------------------

// Kernel-space pointer plausibility: nonzero, canonical, 8-aligned.
bool kptr_plausible(uint64_t p) {
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
    if (gKrwMode == KRW_LIBKRW) {
        return libkrw_kread(addr, buf, len) == 0;
    }
    return kread_buf_tfp0(addr, buf, len) == KERN_SUCCESS;
}

static bool krw_write(uint64_t addr, const void *buf, size_t len) {
    if (gKrwMode == KRW_LIBJB) {
        return libjb_kwritebuf(addr, buf, len) == 0;
    }
    if (gKrwMode == KRW_LIBKRW) {
        // libkrw signature: kwrite(void *from, uint64_t to, size_t len)
        return libkrw_kwrite((void *)buf, addr, len) == 0;
    }
    return kwrite_buf_tfp0(addr, buf, len) == KERN_SUCCESS;
}

bool krw_read32(uint64_t addr, uint32_t *out) {
    return krw_read(addr, out, sizeof(*out));
}

static bool krw_read16(uint64_t addr, uint16_t *out) {
    return krw_read(addr, out, sizeof(*out));
}

static bool krw_write32(uint64_t addr, uint32_t val) {
    return krw_write(addr, &val, sizeof(val));
}

// Pointer read with PAC stripping.
// kreadbuf/kwritebuf primitive + t1sz unsign.
static bool krw_read_ptr(uint64_t addr, uint64_t *out) {
    uint64_t v = 0;
    if (!krw_read(addr, &v, sizeof(v))) return false;
    v = unsign_kptr(v);
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

// Outcome of a vnode flag operation (A5): callers MUST distinguish "failed
// before any write" (safe to close the fd / drop the WAL record) from "write
// attempted, outcome unknown" (the vnode may carry VISSHADOW — retain the fd
// and the WAL record until a VERIFIED clear; never close such an fd).
// (vflag_result_t is declared in krw.h.)

// Set/clear VISSHADOW and READ BACK to verify (spec: read back after writing).
// A28: readback must show the FULL expected value (original with only the
// VISSHADOW bit changed), not just the bit.  Note: this read-modify-write is
// not atomic against a concurrent kernel flag update without the vnode lock;
// the retained fd prevents vnode UAF, and a concurrent flag change would
// surface as a readback mismatch → VFLAG_MAYBE → retained fd + WAL record.
vflag_result_t vnode_set_flag(uint64_t vnode, bool set) {
    uint32_t flags = 0;
    if (!krw_read32(vnode + OFF_VNODE_V_FLAGS, &flags)) {
        shdw_log("vnode_set_flag: read failed at 0x%llx", vnode);
        return VFLAG_FAILED_PRE;
    }
    uint32_t nf = set ? (flags | VISSHADOW) : (flags & ~VISSHADOW);
    if (nf == flags) {
        return VFLAG_OK;   // already in the desired state (verified by the read)
    }
    if (!krw_write32(vnode + OFF_VNODE_V_FLAGS, nf)) {
        shdw_log("vnode_set_flag: write failed at 0x%llx", vnode);
        return VFLAG_MAYBE;
    }
    uint32_t check = 0;
    if (!krw_read32(vnode + OFF_VNODE_V_FLAGS, &check)) {
        shdw_log("vnode_set_flag: readback failed at 0x%llx", vnode);
        return VFLAG_MAYBE;
    }
    if (check != nf) {
        shdw_log("vnode_set_flag: readback mismatch at 0x%llx (got 0x%x, expected 0x%x)",
                 vnode, check, nf);
        return VFLAG_MAYBE;
    }
    return VFLAG_OK;
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
    // the caller retries the whole walk.  The fd table is inline in
    // filedesc (iOS 15+; the version gate is 15.0-16.6.1).
    uint64_t a = 0, b = 0;
    if (!krw_read(filedesc + 8 * fd, &a, sizeof(a))) return false;
    if (!krw_read(filedesc + 8 * fd, &b, sizeof(b))) return false;
    if (a != b) return false;   // relocated between reads
    if (!kptr_plausible(unsign_kptr(a))) return false;
    *out = unsign_kptr(a);
    return true;
}

// Walk: proc → p_fd → fd_ofiles[fd] → f_fglob → fg_data.  Validates every
// step (spec section 2).  The open fd is retained by the caller; this only
// resolves the vnode and captures v_id (required — A24: a failed v_id read
// fails the resolution; vId == 0 must never pass validation).
bool resolve_vnode_for_fd(int fd, uint64_t *outVnode, uint64_t *outVId) {
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

    // fd within table bounds: the entry itself is re-read and validated
    // (canonical, nonzero) — an out-of-bounds read yields garbage and is
    // rejected; our fd is in-bounds by construction (open() succeeded).
    for (int attempt = 0; attempt < 3; attempt++) {
        // A25: re-read proc's p_fd on EVERY attempt and verify it did not
        // change between two consecutive reads — the fd table (or the proc
        // itself) may have relocated; only then walk the entries.
        uint64_t fa = 0, fb = 0;
        if (!krw_read_ptr(proc + off_p_pfd, &fa)) {
            shdw_log("resolve: p_pfd read failed");
            break;
        }
        if (!krw_read_ptr(proc + off_p_pfd, &fb)) {
            shdw_log("resolve: p_pfd read failed (2nd)");
            break;
        }
        if (fa != fb) {
            shdw_log("resolve: p_fd relocated between reads — retrying");
            continue;
        }
        uint64_t filedesc = fa;

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
        // Capture v_id — REQUIRED (A24): both a failed read AND a legitimate
        // zero must fail the resolution (v_id of 0 cannot serve as identity).
        uint32_t vid32 = 0;
        if (!krw_read32(vnode + OFF_VNODE_V_ID, &vid32) || vid32 == 0) {
            shdw_log("resolve: v_id read failed or zero at 0x%llx", vnode);
            break;
        }
        proc_rele_self(proc);
        *outVnode = vnode;
        *outVId = vid32;
        return true;
    }
    proc_rele_self(proc);
    return false;
}
