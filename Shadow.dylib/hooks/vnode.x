#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "hooks.h"
#import <RootBridge.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <mach/vm_page_size.h>
#import <mach/vm_region.h>
#import <mach-o/loader.h>

// Vnode-layer file hiding (kernel memory via KRW). Mechanism (verified
// against XNU sources): open(path, O_RDONLY) → fd-walk proc→p_fd→fd_ofiles
// [fd]→f_fglob→fg_data to get the vnode → v_usecount += 1, v_iocount += 1
// (pin: prevents reclaim/re-instantiation) → v_flag |= VISSHADOW (0x008000;
// kernel namei then returns ENOENT for any path resolution through that
// vnode) → close(fd). Restore clears the flag and decrements both counts.
//
// Two KRW backends, fail soft:
//   1. Dopamine (rootless): dlopen libjailbreak.dylib, dlsym jbdInitPPLRW
//      (+ kread32/kwrite32/kread64/proc_find). jailbreakd rejects non-root
//      callers, so getuid is hooked to 0 for the duration of the call.
//   2. palera1n/legacy (tfp0): task_for_pid(0) + mach_vm_read_overwrite/
//      mach_vm_write, our proc found via the pfinder allproc scan
//      ("shutdownwait" xref → msleep → allproc).
// Any failure logs once, disables the feature, and returns — never crash,
// never proceed with partial init.
//
// State file (crash safety): pid + vnode addresses. Leaked vnode refs panic
// the kernel at shutdown if never restored; the file is restored by the next
// process init and by SpringBoard's ctor (system-wide janitor).

#if defined(__arm64__) || defined(__arm64e__)

// ---- offset table ----
// vnode offsets are CONSTANT across iOS 12-18.
#define VISSHADOW 0x008000

#ifndef kCFCoreFoundationVersionNumber_iOS_12_0
#define kCFCoreFoundationVersionNumber_iOS_12_0 (1535.12)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_13_0
#define kCFCoreFoundationVersionNumber_iOS_13_0 (1656)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_14_0
#define kCFCoreFoundationVersionNumber_iOS_14_0 (1740)
#endif
#define kCFCoreFoundationVersionNumber_iOS_15_0 (1854)
#define kCFCoreFoundationVersionNumber_iOS_15_2 (1856.105)

static uint32_t off_p_pid = 0;
static uint32_t off_p_pfd = 0;
static uint32_t off_fd_ofiles = 0;
static uint32_t off_fp_fglob = 0;
static uint32_t off_fg_data = 0;
static uint32_t off_vnode_iocount = 0;
static uint32_t off_vnode_usecount = 0;
static uint32_t off_vnode_vflags = 0;

static unsigned long long t1sz_boot = 0;

static bool shdw_isArm64e(void) {
    cpu_subtype_t subtype;
    size_t cpusz = sizeof(cpu_subtype_t);
    sysctlbyname("hw.cpusubtype", &subtype, &cpusz, NULL, 0);
    return (subtype == 2 /* CPU_SUBTYPE_ARM64E */);
}

// PAC-unsign a kernel pointer (vnb-xfdxh kernel.m verbatim).
static uint64_t unsign_kptr(uint64_t pac_kaddr) {
    if(t1sz_boot == 0) {
        return pac_kaddr;
    }

    if ((pac_kaddr & 0xFFFFFF0000000000) == 0xFFFFFF0000000000) {
        return pac_kaddr;
    }
    if(t1sz_boot != 0) {
        return pac_kaddr |= ~((1ULL << (64U - t1sz_boot)) - 1U);
    }
    return pac_kaddr;
}

static int offset_init(void) {
    char kern_version[512] = {};
    size_t kern_version_size = sizeof(kern_version);
    sysctlbyname("kern.version", &kern_version, &kern_version_size, NULL, 0);

    if(shdw_isArm64e()) {
        if(strstr(kern_version, "T8120") != NULL || strstr(kern_version, "T8103") != NULL || strstr(kern_version, "T8112") != NULL)
            t1sz_boot = 17;
        else
            t1sz_boot = 25;
    } else {
        t1sz_boot = 0;
    }

    // vnode offsets (constant across iOS 12-18)
    off_vnode_iocount = 0x64;
    off_vnode_usecount = 0x60;
    off_vnode_vflags = 0x54;

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_2) {
        // ios 15.2 ~ 16.x (kernel.m)
        NSLog(@"[Shadow] vnode: iOS 15.2+ offsets");
        off_p_pid = 0x68;
        off_p_pfd = 0xf8;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_0) {
        // ios 15.0-15.1.1 (kernel.m)
        NSLog(@"[Shadow] vnode: iOS 15.0-15.1.1 offsets");
        off_p_pid = 0x68;
        off_p_pfd = 0x100;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_14_0) {
        // ios 14 (vnb-zero kernel.m row; plus007 has no distinct iOS 14 row)
        NSLog(@"[Shadow] vnode: iOS 14 offsets");
        off_p_pid = 0x68;
        off_p_pfd = 0xf8;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0) {
        // ios 13 (plus007 kstruct_offsets_13_0)
        NSLog(@"[Shadow] vnode: iOS 13 offsets");
        off_p_pid = 0x68;
        off_p_pfd = 0x108;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0) {
        // ios 12 (plus007 kstruct_offsets_12_0)
        NSLog(@"[Shadow] vnode: iOS 12 offsets");
        off_p_pid = 0x60;
        off_p_pfd = 0x100;
        off_fd_ofiles = 0x0;
        off_fp_fglob = 0x10;
        off_fg_data = 0x38;
        return 0;
    }

    return -1;
}

// ---- KRW backends ----
typedef enum {
    KRW_NONE = 0,
    KRW_LIBJB,   // Dopamine: libjailbreak.dylib (PPL r/w)
    KRW_TFP0     // palera1n/legacy: task_for_pid(0) + mach_vm r/w
} shdw_krw_mode_t;

static shdw_krw_mode_t shdw_krw_mode = KRW_NONE;
static HKSubstitutor* shdw_hooks = NULL;  // set by shadowhook_vnode
static uint64_t shdw_proc = 0;            // our proc (both backends)

static void* libjb = NULL;
static uint64_t (*libjb_proc_find)(pid_t pidToFind) = NULL;
static uint32_t (*libjb_kread32)(uint64_t va) = NULL;
static uint64_t (*libjb_kread64)(uint64_t va) = NULL;
static void (*libjb_kwrite32)(uint64_t va, uint32_t v) = NULL;

static bool did_jbdInitPPLRW = false;

// jailbreakd rejects non-root callers of jbdInitPPLRW; getuid is hooked to 0
// for the duration of the call (kernel.m verbatim — the hook passes through
// once init is done).
static uid_t (*orig_getuid)(void);
static uid_t hook_getuid(void) {
    if(did_jbdInitPPLRW) return orig_getuid();
    return 0;
}

static int krw_init_libjb(void) {
    libjb = dlopen([[RootBridge getJBPath:@"/basebin/libjailbreak.dylib"] UTF8String], RTLD_NOW);
    if(!libjb) {
        return 1;
    }

    if(!did_jbdInitPPLRW) {
        // hook getuid to 0, bypass protection when calling jbdInitPPLRW.
        // Only needed when we're not already uid 0, and only possible when a
        // substitutor is at hand — SpringBoard's early-path restore runs as
        // root and has none. MSHookFunction routes through the fishhook
        // backend (rebind_symbols semantics: patches all loaded images,
        // including the just-dlopen'd libjailbreak.dylib).
        if(getuid() != 0 && shdw_hooks) {
            #ifdef hookkit_h
            HKSubstitutor* hooks = shdw_hooks;  // macro references `hooks`
            #endif
            MSHookFunction(getuid, hook_getuid, (void **)&orig_getuid);
        }

        int (*jbdInitPPLRW)(void) = (int (*)(void))dlsym(libjb, "jbdInitPPLRW");
        if(!jbdInitPPLRW) {
            return 1;
        }
        if(jbdInitPPLRW() != 0) {
            return 1;
        }
    }
    did_jbdInitPPLRW = true;

    libjb_proc_find = (uint64_t (*)(pid_t))dlsym(libjb, "proc_find");
    libjb_kread32 = (uint32_t (*)(uint64_t))dlsym(libjb, "kread32");
    libjb_kread64 = (uint64_t (*)(uint64_t))dlsym(libjb, "kread64");
    libjb_kwrite32 = (void (*)(uint64_t, uint32_t))dlsym(libjb, "kwrite32");
    if(!libjb_proc_find || !libjb_kread32 || !libjb_kread64 || !libjb_kwrite32) {
        return 1;
    }

    return 0;
}

// ---- tfp0 backend (plus007 main.m verbatim) ----
typedef uint64_t kaddr_t;

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

// (mach_vm_* forward declarations, verbatim from main.m — identical to the
// mach_vm.h declarations, kept for fidelity)
kern_return_t
        mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
        mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
        mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
        mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
    return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
    return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static kern_return_t
init_tfp0(void) {
    kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
    mach_port_t host;
    pid_t pid;

    if(ret != KERN_SUCCESS) {
        host = mach_host_self();
        if(MACH_PORT_VALID(host)) {
            NSLog(@"[Shadow] vnode: host: 0x%x", host);
            ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
            NSLog(@"[Shadow] vnode: unc0ver-style host special port, load it anyway");
            return ret;     // TO USE UNC0VER, TEMPORARY
        }
        mach_port_deallocate(mach_task_self(), host);
    }
    if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
        if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
            return ret;
        }
        mach_port_deallocate(mach_task_self(), tfp0);
    }
    NSLog(@"[Shadow] vnode: failed to init tfp0");
    return KERN_FAILURE;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_vm_size_t read_sz, out_sz = 0;

    while(sz != 0) {
        read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
            return KERN_FAILURE;
        }
        p += read_sz;
        sz -= read_sz;
        addr += read_sz;
    }
    return KERN_SUCCESS;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
    return kread_buf(addr, val, sizeof(*val));
}

static kern_return_t
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
    vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_msg_type_number_t write_sz;

    while(sz != 0) {
        write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
            return KERN_FAILURE;
        }
        p += write_sz;
        sz -= write_sz;
        addr += write_sz;
    }
    return KERN_SUCCESS;
}

static kaddr_t
get_kbase(kaddr_t *kslide) {
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    vm_region_extended_info_data_t extended_info;
    task_dyld_info_data_t dyld_info;
    kaddr_t addr, rtclock_datap;
    struct mach_header_64 mh64;
    mach_port_t obj_nm;
    mach_vm_size_t sz;

    if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS && dyld_info.all_image_info_size != 0) {
        *kslide = dyld_info.all_image_info_size;
        return VM_KERNEL_LINK_ADDRESS + *kslide;
    }
    cnt = VM_REGION_EXTENDED_INFO_COUNT;
    for(addr = 0; mach_vm_region(tfp0, &addr, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&extended_info, &cnt, &obj_nm) == KERN_SUCCESS; addr += sz) {
        mach_port_deallocate(mach_task_self(), obj_nm);
        if(extended_info.user_tag == VM_KERN_MEMORY_CPU && extended_info.protection == VM_PROT_DEFAULT) {
            if(kread_addr(addr + CPU_DATA_RTCLOCK_DATAP_OFF, &rtclock_datap) != KERN_SUCCESS) {
                break;
            }
            NSLog(@"[Shadow] vnode: rtclock_datap: 0x%llx", rtclock_datap);
            rtclock_datap = trunc_page_kernel(rtclock_datap);
            do {
                if(rtclock_datap <= VM_KERNEL_LINK_ADDRESS) {
                    return 0;
                }
                rtclock_datap -= vm_kernel_page_size;
                if(kread_buf(rtclock_datap, &mh64, sizeof(mh64)) != KERN_SUCCESS) {
                    return 0;
                }
            } while(mh64.magic != MH_MAGIC_64 || mh64.cputype != CPU_TYPE_ARM64 || mh64.filetype != MH_EXECUTE);
            *kslide = rtclock_datap - VM_KERNEL_LINK_ADDRESS;
            return rtclock_datap;
        }
    }
    return 0;
}

static kern_return_t
find_section(kaddr_t sg64_addr, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
    kaddr_t s64_addr, s64_end;

    for(s64_addr = sg64_addr + sizeof(sg64), s64_end = s64_addr + (sg64.cmdsize - sizeof(*sp)); s64_addr < s64_end; s64_addr += sizeof(*sp)) {
        if(kread_buf(s64_addr, sp, sizeof(*sp)) != KERN_SUCCESS) {
            break;
        }
        if(strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
            return KERN_SUCCESS;
        }
    }
    return KERN_FAILURE;
}

static void
sec_reset(sec_64_t *sec) {
    memset(&sec->s64, '\0', sizeof(sec->s64));
    sec->data = NULL;
}

static void
sec_term(sec_64_t *sec) {
    free(sec->data);
    sec_reset(sec);
}

static kern_return_t
sec_init(sec_64_t *sec) {
    if((sec->data = malloc(sec->s64.size)) != NULL) {
        if(kread_buf(sec->s64.addr, sec->data, sec->s64.size) == KERN_SUCCESS) {
            return KERN_SUCCESS;
        }
        sec_term(sec);
    }
    return KERN_FAILURE;
}

static void
pfinder_reset(pfinder_t *pfinder) {
    sec_reset(&pfinder->sec_text);
    sec_reset(&pfinder->sec_cstring);
}

static void
pfinder_term(pfinder_t *pfinder) {
    sec_term(&pfinder->sec_text);
    sec_term(&pfinder->sec_cstring);
    pfinder_reset(pfinder);
}

static kern_return_t
pfinder_init(pfinder_t *pfinder, kaddr_t kbase) {
    kern_return_t ret = KERN_FAILURE;
    struct segment_command_64 sg64;
    kaddr_t sg64_addr, sg64_end;
    struct mach_header_64 mh64;
    struct section_64 s64;

    pfinder_reset(pfinder);
    if(kread_buf(kbase, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
        for(sg64_addr = kbase + sizeof(mh64), sg64_end = sg64_addr + (mh64.sizeofcmds - sizeof(sg64)); sg64_addr < sg64_end; sg64_addr += sg64.cmdsize) {
            if(kread_buf(sg64_addr, &sg64, sizeof(sg64)) != KERN_SUCCESS) {
                break;
            }
            if(sg64.cmd == LC_SEGMENT_64) {
                if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_TEXT, &s64) == KERN_SUCCESS) {
                    pfinder->sec_text.s64 = s64;
                    NSLog(@"[Shadow] vnode: sec_text_addr: 0x%llx, sec_text_sz: 0x%llx", s64.addr, s64.size);
                } else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0 && find_section(sg64_addr, sg64, SECT_CSTRING, &s64) == KERN_SUCCESS) {
                    pfinder->sec_cstring.s64 = s64;
                    NSLog(@"[Shadow] vnode: sec_cstring_addr: 0x%llx, sec_cstring_sz: 0x%llx", s64.addr, s64.size);
                }
            }
            if(pfinder->sec_text.s64.size != 0 && pfinder->sec_cstring.s64.size != 0) {
                if(sec_init(&pfinder->sec_text) == KERN_SUCCESS) {
                    ret = sec_init(&pfinder->sec_cstring);
                }
                break;
            }
        }
    }
    if(ret != KERN_SUCCESS) {
        pfinder_term(pfinder);
    }
    return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
    uint64_t x[32] = { 0 };
    uint32_t insn;

    for(; start >= pfinder.sec_text.s64.addr && start < pfinder.sec_text.s64.addr + (pfinder.sec_text.s64.size - sizeof(insn)); start += sizeof(insn)) {
        memcpy(&insn, pfinder.sec_text.data + (start - pfinder.sec_text.s64.addr), sizeof(insn));
        if(IS_LDR_X(insn)) {
            x[RD(insn)] = start + LDR_X_IMM(insn);
        } else if(IS_ADR(insn)) {
            x[RD(insn)] = start + ADR_IMM(insn);
        } else if(IS_ADRP(insn)) {
            x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
            continue;
        } else if(IS_ADD_X(insn)) {
            x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
        } else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
            x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
        } else if(IS_RET(insn)) {
            memset(x, '\0', sizeof(x));
        }
        if(RD(insn) == rd) {
            if(to == 0) {
                return x[rd];
            }
            if(x[rd] == to) {
                return start;
            }
        }
    }
    return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
    const char *p, *e;
    size_t len;

    for(p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p < e; p += len) {
        len = strlen(p) + 1;
        if(strncmp(str, p, len) == 0) {
            return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
        }
    }
    return 0;
}

static kaddr_t
pfinder_allproc(pfinder_t pfinder) {
    kaddr_t ref = pfinder_xref_str(pfinder, "shutdownwait", 2);

    if(ref == 0) {
        ref = pfinder_xref_str(pfinder, "shutdownwait", 3);                                                 /* msleep */
    }
    return pfinder_xref_rd(pfinder, 8, ref, 0);
}

static kern_return_t
pfinder_init_offsets(pfinder_t pfinder) {
    if((allproc = pfinder_allproc(pfinder)) != 0) {
        NSLog(@"[Shadow] vnode: allproc: 0x%llx", allproc);
        return KERN_SUCCESS;
    }
    return KERN_FAILURE;
}

// pfinder-style allproc scan for our own proc (plus007 find_task verbatim,
// returning the proc pointer instead of the task — we never need the task).
static uint64_t
find_our_proc(pid_t pid) {
    kaddr_t cur = allproc;
    pid_t cur_pid;

    while(kread_addr(cur, &cur) == KERN_SUCCESS && cur != 0) {
        if(kread_buf(cur + off_p_pid, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS && cur_pid == pid) {
            NSLog(@"[Shadow] vnode: proc: 0x%llx", cur);
            return cur;
        }
    }
    return 0;
}

static int krw_init_tfp0(void) {
    kaddr_t kbase, kslide;
    pfinder_t pfinder;

    if(init_tfp0() != KERN_SUCCESS) {
        return 1;
    }

    if((kbase = get_kbase(&kslide)) == 0) {
        return 1;
    }
    NSLog(@"[Shadow] vnode: kbase: 0x%llx, kslide: 0x%llx", kbase, kslide);

    if(pfinder_init(&pfinder, kbase) != KERN_SUCCESS) {
        return 1;
    }
    if(pfinder_init_offsets(pfinder) != KERN_SUCCESS) {
        pfinder_term(&pfinder);
        return 1;
    }
    pfinder_term(&pfinder);

    shdw_proc = find_our_proc(getpid());
    if(shdw_proc == 0) {
        return 1;
    }
    return 0;
}

// ---- unified kread/kwrite dispatch ----
static uint32_t
kread32(uint64_t va) {
    if(shdw_krw_mode == KRW_LIBJB) {
        return libjb_kread32(va);
    }
    uint32_t out = 0;
    kread_buf(va, &out, sizeof(out));
    return out;
}

static uint64_t
kread64(uint64_t va) {
    if(shdw_krw_mode == KRW_LIBJB) {
        return libjb_kread64(va);
    }
    uint64_t out = 0;
    kread_addr(va, &out);
    return out;
}

static void
kwrite32(uint64_t va, uint32_t v) {
    if(shdw_krw_mode == KRW_LIBJB) {
        libjb_kwrite32(va, v);
        return;
    }
    uint32_t _v = v;
    kwrite_buf(va, &_v, sizeof(_v));
}

static uint64_t
shdw_proc_find(pid_t pidToFind) {
    if(shdw_krw_mode == KRW_LIBJB) {
        return libjb_proc_find(pidToFind);
    }
    return shdw_proc;
}

// get vnode via fd-walk proc→p_fd→fd_ofiles[fd]→f_fglob→fg_data
static uint64_t
getVnodeAtPath(const char* filename) {
    int file_index = open(filename, O_RDONLY);
    if(file_index == -1) return -1;

    uint64_t proc = shdw_proc_find(getpid());
    if(proc == 0) {
        close(file_index);
        return -1;
    }

    uint64_t filedesc_pac = kread64(proc + off_p_pfd);
    uint64_t filedesc = unsign_kptr(filedesc_pac);
    uint64_t openedfile = 0;
    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_15_0) {
        // iOS 15+: ofiles array is inline at filedesc (kernel.m verbatim).
        openedfile = kread64(filedesc + (8 * file_index));
    } else {
        // iOS 12-14: fd_ofiles is a pointer to the ofiles array
        // (plus007/vnb-zero verbatim).
        uint64_t fileproc = kread64(filedesc + off_fd_ofiles);
        openedfile = kread64(fileproc + (8 * file_index));
    }
    uint64_t fileglob_pac = kread64(openedfile + off_fp_fglob);
    uint64_t fileglob = unsign_kptr(fileglob_pac);
    uint64_t vnode_pac = kread64(fileglob + off_fg_data);
    uint64_t vnode = unsign_kptr(vnode_pac);

    close(file_index);

    return vnode;
}

// hide and show file using vnode
static void
hide_path(uint64_t vnode) {
    uint32_t v_flags = kread32(vnode + off_vnode_vflags);
    kwrite32(vnode + off_vnode_vflags, (v_flags | VISSHADOW));
}

static void
show_path(uint64_t vnode) {
    if(vnode == 0) {
        NSLog(@"[Shadow] vnode: vnode is 0x0, skip show_path");
        return;
    }
    uint32_t v_flags = kread32(vnode + off_vnode_vflags);
    kwrite32(vnode + off_vnode_vflags, (v_flags &= ~VISSHADOW));
}

// Feature flag: "VnodeHiding" in Shadow's prefs plist (default OFF), read
// from both the rootless and plain locations; forced ON when a detection
// library is present (escalation, same pattern as dyld.x memory hiding).
static BOOL
shdw_vnode_hiding_enabled(void) {
    if(shdw_detector_present) {
        return YES;
    }

    static BOOL enabled = NO;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        for(NSString* path in @[
            [RootBridge getJBPath:@(SHADOW_PREFS_PLIST)],
            @(SHADOW_PREFS_PLIST)
        ]) {
            NSDictionary* prefs = [NSDictionary dictionaryWithContentsOfFile:path];

            if(prefs) {
                enabled = [prefs[@"VnodeHiding"] boolValue];
                break;
            }
        }
    });

    return enabled;
}

#define SHADOW_VNODE_STATE "/var/mobile/Library/Preferences/me.n.utility.vnodes.plist"

// Restore pinned+hidden vnodes recorded by a previous process: clear
// VISSHADOW, decrement both counts (guarded > 0), then delete the file.
// (vnode.m recoveryVnode verbatim, adapted to plist + flag clear.)
static void
shdw_restore_state(void) {
    NSDictionary* state = [NSDictionary dictionaryWithContentsOfFile:@(SHADOW_VNODE_STATE)];

    if(!state) {
        NSLog(@"[Shadow] vnode: state file unreadable, removing");
        [[NSFileManager defaultManager] removeItemAtPath:@(SHADOW_VNODE_STATE) error:nil];
        return;
    }

    for(NSNumber* num in state[@"vnodes"]) {
        uint64_t savedVnode = [num unsignedLongLongValue];
        if(savedVnode == 0) continue;
        NSLog(@"[Shadow] vnode: restoring 0x%llx", savedVnode);
        show_path(savedVnode);
        if(kread32(savedVnode + off_vnode_iocount) > 0)
            kwrite32(savedVnode + off_vnode_iocount, kread32(savedVnode + off_vnode_iocount) - 1);
        if(kread32(savedVnode + off_vnode_usecount) > 0)
            kwrite32(savedVnode + off_vnode_usecount, kread32(savedVnode + off_vnode_usecount) - 1);
    }

    [[NSFileManager defaultManager] removeItemAtPath:@(SHADOW_VNODE_STATE) error:nil];
}

// HIDE LIST. Paths that fail to open don't exist yet (e.g. prefs plist on
// first launch) and are skipped. getJBPath resolves the rootless (/var/jb)
// variant and passes the rootful path through unchanged.
static void
shdw_hide_paths(void) {
    // The tweak's own dylib path. dladdr is hooked (dyld.x) but passes
    // through for tweak callers via isCallerTweak — verified safe.
    NSString* dylibPath = nil;
    Dl_info info;
    if(dladdr(&shdw_detector_present, &info) != 0 && info.dli_fname && info.dli_fname[0]) {
        dylibPath = [NSString stringWithUTF8String:info.dli_fname];
    }

    NSMutableArray* hidePaths = [NSMutableArray array];
    if(dylibPath) {
        [hidePaths addObject:dylibPath];
    }
    [hidePaths addObject:[RootBridge getJBPath:@"/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib"]];
    [hidePaths addObject:[RootBridge getJBPath:@"/Library/PreferenceBundles/ShadowSettings.bundle"]];
    [hidePaths addObject:@(SHADOW_PREFS_PLIST)];
    [hidePaths addObject:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];

    NSMutableArray* hiddenPaths = [NSMutableArray array];
    NSMutableArray* hiddenVnodes = [NSMutableArray array];

    for(NSString* path in [NSOrderedSet orderedSetWithArray:hidePaths]) {
        uint64_t vnode = getVnodeAtPath([path UTF8String]);

        if(vnode == (uint64_t)-1) {
            NSLog(@"[Shadow] vnode: skip (no such file): %@", path);
            continue;
        }
        if(vnode == 0) {
            NSLog(@"[Shadow] vnode: skip (vnode lookup failed): %@", path);
            continue;
        }

        // Pin: prevents reclaim/re-instantiation of the vnode.
        kwrite32(vnode + off_vnode_usecount, kread32(vnode + off_vnode_usecount) + 1);
        kwrite32(vnode + off_vnode_iocount, kread32(vnode + off_vnode_iocount) + 1);

        // Hide: kernel namei returns ENOENT through this vnode.
        hide_path(vnode);

        [hiddenPaths addObject:path];
        [hiddenVnodes addObject:@(vnode)];
        NSLog(@"[Shadow] vnode: hidden 0x%llx: %@", vnode, path);
    }

    if([hiddenVnodes count]) {
        // Crash safety: leaked vnode refs panic the kernel at shutdown if
        // never restored. Write pid + vnode addresses for the janitor
        // (SpringBoard ctor / next launch).
        NSDictionary* state = @{
            @"pid": @(getpid()),
            @"vnodes": hiddenVnodes
        };

        if(![state writeToFile:@(SHADOW_VNODE_STATE) atomically:YES]) {
            NSLog(@"[Shadow] vnode: FAILED to write state file — kernel panic risk if never restored!");
        }
    }

    // Verify-after-hide (device verification aid): raw syscall access check
    // (plus007 main.m verbatim semantics).
    for(NSString* path in hiddenPaths) {
        int detectFlag = syscall(SYS_access, [path UTF8String], F_OK);
        if(detectFlag == 0) {
            NSLog(@"[Shadow] vnode: NOT hidden: %@", path);
        } else if(detectFlag == -1) {
            NSLog(@"[Shadow] vnode: hidden: %@", path);
        }
    }
}

static int shdw_krw_state = 0;  // 0 = uninit, 1 = ready, -1 = failed (logged once)

static int
shdw_krw_init(void) {
    if(shdw_krw_state != 0) {
        return shdw_krw_state;
    }

    if(offset_init() != 0) {
        NSLog(@"[Shadow] vnode: offset init failed, feature disabled");
        shdw_krw_state = -1;
        return -1;
    }

    if(krw_init_libjb() == 0) {
        shdw_krw_mode = KRW_LIBJB;
        shdw_proc = shdw_proc_find(getpid());
        if(shdw_proc == 0) {
            NSLog(@"[Shadow] vnode: proc_find failed, feature disabled");
            shdw_krw_state = -1;
            return -1;
        }
        shdw_krw_state = 1;
        return 1;
    }

    NSLog(@"[Shadow] vnode: libjailbreak unavailable, trying tfp0");
    if(krw_init_tfp0() == 0) {
        shdw_krw_mode = KRW_TFP0;
        shdw_krw_state = 1;
        return 1;
    }

    NSLog(@"[Shadow] vnode: krw init failed, feature disabled");
    shdw_krw_state = -1;
    return -1;
}

void shadowhook_vnode(HKSubstitutor* hooks) {
    shdw_hooks = hooks;

    if(!shdw_vnode_hiding_enabled()) {
        return;
    }

    if(shdw_krw_init() != 1) {
        return;
    }

    // Restore any leaked state from a previous run (previous process died
    // while vnodes were hidden+pinned), then hide fresh and write new state.
    if([[NSFileManager defaultManager] fileExistsAtPath:@(SHADOW_VNODE_STATE)]) {
        NSLog(@"[Shadow] vnode: restoring leaked state from previous process");
        shdw_restore_state();
    }

    shdw_hide_paths();
}

void shadowhook_vnode_restore(void) {
    // System-wide janitor (SpringBoard ctor): restore leaked state without
    // hiding anything new. Runs regardless of the VnodeHiding pref — a
    // previous run may have left pinned vnodes behind.
    if(![[NSFileManager defaultManager] fileExistsAtPath:@(SHADOW_VNODE_STATE)]) {
        return;
    }

    if(shdw_krw_init() != 1) {
        return;
    }

    NSLog(@"[Shadow] vnode: restoring leaked state");
    shdw_restore_state();
}

#else

// 32-bit armv7: compiled out — kernel-address code, 32-bit offsets
// unmaintained.
void shadowhook_vnode(HKSubstitutor* hooks) {
    (void)hooks;
}

void shadowhook_vnode_restore(void) {
}

#endif
