//
//  krw.h
//  shadowd
//
//  Kernel read/write + vnode ops (extracted from main.m — A6).  Everything a
//  krw caller in main.m needs: the offset table, backend state, and the
//  exported read/write/flag helpers.
//

#ifndef shadowd_krw_h
#define shadowd_krw_h

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>

// Daemon logging (defined in main.m).
extern void shdw_log(const char *fmt, ...);

// Version gate state (Darwin major/minor, parsed in main.m's darwin_version;
// offset_init dispatches off the major).
extern int gDarwinMajor;
extern int gDarwinMinor;

// vnode flag + offset table.  iOS 16 uses p_pid 0x60 (Dopamine libjailbreak
// info.c); iOS 12 f_fglob is 0x8.  vnode offsets are constant.
#define VISSHADOW 0x008000
#define OFF_VNODE_V_FLAGS    0x54
#define OFF_VNODE_V_USECOUNT 0x60   // read-only validation only — never edited
#define OFF_VNODE_V_IOCOUNT  0x64   // read-only validation only — never edited
#define OFF_VNODE_V_TYPE     0x70   // uint16; jelbrekLib offsetof.c
#define OFF_VNODE_V_ID       0x74   // uint32; jelbrekLib offsetof.c

#ifndef kCFCoreFoundationVersionNumber_iOS_15_0
#define kCFCoreFoundationVersionNumber_iOS_15_0 (1854)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_15_2
#define kCFCoreFoundationVersionNumber_iOS_15_2 (1856.105)
#endif
#ifndef kCFCoreFoundationVersionNumber_iOS_17_0
#define kCFCoreFoundationVersionNumber_iOS_17_0 (2050)
#endif

// krw init retry (background thread, 2s * 15 = 30s).
#define KRW_RETRY_INTERVAL 2
#define KRW_RETRY_MAX      15

typedef enum {
    KRW_NONE = 0,
    KRW_LIBJB,   // Dopamine: libjailbreak.dylib (PPL r/w)
    KRW_LIBKRW,  // rootless: Siguza libkrw0 (libkrw.0.dylib)
    KRW_TFP0     // legacy: task_for_pid(0) + mach_vm r/w
} krw_mode_t;

typedef enum {
    KRW_INIT = 0,      // init in progress (background, with backoff)
    KRW_READY = 1,
    KRW_DISABLED = -1,
} krw_state_t;

extern krw_mode_t gKrwMode;
// gKrwState is written on the background init thread and read on the kernel
// queue — volatile is NOT synchronization.  Use C11 atomics.
extern _Atomic krw_state_t gKrwState;

// Outcome of a vnode flag operation: callers MUST distinguish "failed before
// any write" (safe to close the fd / drop the WAL record) from "write
// attempted, outcome unknown" (the vnode may carry VISSHADOW — retain the fd
// and the WAL record until a VERIFIED clear; never close such an fd).
typedef enum {
    VFLAG_OK = 0,        // desired state verified by readback
    VFLAG_FAILED_PRE,    // failed before any write was attempted
    VFLAG_MAYBE,         // write attempted, state unverified — may be hidden
} vflag_result_t;

// One init attempt for each backend (retried by krw_init_background).
int krw_init_libjb_once(void);
int krw_init_libkrw_once(void);
int krw_init_tfp0(void);

// True when libjailbreak.dylib is installed (Dopamine-family rootless
// builds; plain palera1n ships libkrw instead).  Also performs the first
// dlopen, so krw_init_libjb_once reuses the handle.
bool krw_libjb_present(void);

// Row offsets + t1sz_boot — must be in place before ANY krw work.
int offset_init(void);

bool is_arm64e(void);

bool krw_read32(uint64_t addr, uint32_t *out);

// Set/clear VISSHADOW and READ BACK to verify.
vflag_result_t vnode_set_flag(uint64_t vnode, bool set);

// Kernel-space pointer plausibility: nonzero, canonical, 8-aligned.
bool kptr_plausible(uint64_t p);

// Walk: proc → p_fd → fd_ofiles[fd] → f_fglob → fg_data (retained-fd design).
bool resolve_vnode_for_fd(int fd, uint64_t *outVnode, uint64_t *outVId);

#endif /* shadowd_krw_h */
