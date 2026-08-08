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

// t1sz_boot + row dispatch (kernel.m verbatim).
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

    // iOS 15.2+ is split by Darwin major (A1): p_pid is 0x68 on iOS 15
    // (Darwin 21) and 0x60 only on iOS 16 (Darwin 22).
    if (gDarwinMajor == 22) {
        // ios 16.x — p_pid 0x60 per Dopamine libjailbreak info.c
        shdw_log("offsets: iOS 16 (p_pid 0x60, p_pfd 0xf8)");
        off_p_pid = 0x60;
        off_p_pfd = 0xf8;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_2) {
        // ios 15.2 ~ 15.7.x — p_pid 0x68 (Darwin 21)
        shdw_log("offsets: iOS 15.2+ (p_pid 0x68, p_pfd 0xf8)");
        off_p_pid = 0x68;
        off_p_pfd = 0xf8;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }
    if (kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_0) {
        // ios 15.0-15.1.1
        shdw_log("offsets: iOS 15.0-15.1.1 (p_pid 0x68, p_pfd 0x100)");
        off_p_pid = 0x68;
        off_p_pfd = 0x100;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }
    return -1;
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

    while (kread_buf_tfp0(cur, &cur, sizeof(cur)) == KERN_SUCCESS && cur != 0) {
        if (kread_buf_tfp0(cur + off_p_pid, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
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
    return kread_buf_tfp0(addr, buf, len) == KERN_SUCCESS;
}

static bool krw_write(uint64_t addr, const void *buf, size_t len) {
    if (gKrwMode == KRW_LIBJB) {
        return libjb_kwritebuf(addr, buf, len) == 0;
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
