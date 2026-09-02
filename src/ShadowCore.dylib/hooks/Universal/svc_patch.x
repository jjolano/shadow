#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Raw svc interception (the "Accepted Residual" from HOOK-FIX-PLAN.md:216):
// inline `svc` syscalls never pass through libc wrappers, so the
// syscall(2)/__syscall(2) hooks in syscall.x cannot see them. Real (non-
// public) detectors emit their own svc sites in their own code and query
// jailbreak paths directly.
//
// This file scans every loaded image's __TEXT for the ARM64 svc opcode
// (the 16-bit immediate varies between emitters; XNU ignores it) and
// redirects each site with a `bl` to a naked trampoline. The trampoline
// applies the SAME path policy as the syscall(2) dispatch (RawSyscalls.def
// categories + isCPathRestricted / shdw_at_path_denied) and, when denied,
// either rewrites the caller's path buffer in place (natural-ENOENT rewrite,
// see the helper below) or returns the synthetic raw-svc error the kernel
// would have produced for a real ENOENT: x0 = 2 with the carry flag set
// (the arm64 syscall convention; libc wrappers and detectors alike read
// carry via cset/b.cs). Allowed calls execute the original svc and return
// with the kernel's own register/flag state.
//
// Recursion safety: the trampoline helper calls libc (getcwd/F_GETPATH via
// the *at policy) and Foundation (isCPathRestricted), so system images
// (/System, /usr) are NEVER patched — a patched libSystem svc site would
// re-enter the trampoline from inside the helper. Detector code lives in
// the app bundle and third-party dylibs, which is exactly what gets
// scanned. Shadow's own images are skipped too (the trampolines' own svc
// sites must never be re-patched, and Shadow's code sees truth anyway).
//
// Every live-code write is serialized and wrapped in a stop-the-world window:
// task_threads() snapshots the process, every other thread is suspended for
// vm_protect/write/reprotect, then resumed. A concurrent trigger waits on the
// same recursive lock; a thread created after the snapshot can still run, so
// the patch remains fail-soft if the protection change cannot be made.
//
// Ceilings (ponytail): (1) only PATH/AT categories are filtered — raw-svc
// ptrace PT_DENY_ATTACH and sysctl probes still bypass (pre-existing
// exposure, separate vector); (2) sites farther than ±128MB from the
// trampoline (bl range) are skipped fail-soft; (3) JIT'd and anonymous
// executable mappings are intentionally not patched: live scanning can
// destabilize an app, so raw-svc coverage is limited to loaded images; (4)
// arm64-only:
// the rootful-legacy armv7 lane gets an empty installer (the ARM64 svc
// convention and this file's encoding scan are arm64 — an armv7 port would
// need the Thumb/ARM-mode encodings).
//
// A kernel-side sysent hook was considered (catch every svc, JIT or not)
// but is not implementable on modern iOS: sy_call must point at
// kernel-resident code, and arm64e's PPL forbids executing injected kernel
// memory — modern jailbreaks patch kernel data only.

#import "UniversalHooks.h"
#import "../../policy/PathPolicy.h"
#import "path_rewrite.h"

#import <libkern/OSCacheControl.h>
#import <pthread.h>
#import <sys/syscall.h>
#import <fcntl.h>

#if defined(__arm64__)

// --- Natural-ENOENT rewrite (call-time path munging) ------------------------
// Prototype: for read-only path syscalls denied by the policy, rewrite the
// caller's path buffer in place (same length, middle of the final component
// → 0x01, see path_rewrite.c) and return "allow": the original svc then
// executes against the munged path and the kernel produces a REAL ENOENT.
// The rewritten buffer stays munged in the app's memory, so every later
// lookup of the same buffer — libc, NSFileManager, a helper process via
// argv — fails naturally, even through code Shadow does not hook. Falls back
// to the synthetic ENOENT when the buffer is not writable (e.g. a __TEXT
// string constant), the syscall is not in the rewrite set, or the
// Universal_PathRewrite is off. open-family with O_CREAT keeps the synthetic deny
// — the munged path would otherwise be CREATED as a side effect.
static BOOL shdw_svc_rewriteable(int sysno, uint64_t flags) {
    switch(sysno) {
        case SYS_access: case SYS_stat: case SYS_lstat:
        case SYS_stat64: case SYS_lstat64:
        case SYS_stat_extended: case SYS_lstat_extended:
        case SYS_stat64_extended: case SYS_lstat64_extended:
        case SYS_getattrlist: case SYS_getxattr: case SYS_listxattr:
        case SYS_readlink: case SYS_pathconf:
        case SYS_fstatat: case SYS_fstatat64:
        case SYS_execve:
            return YES;
        case SYS_open: case SYS_open_extended: case SYS_openat:
            return ((int)flags & O_CREAT) == 0;
        default:
            return NO;
    }
}

// --- Trampoline helper ------------------------------------------------------
// Runs with the app's registers saved on the stack (see the trampoline
// asm). A normal C function: may clobber x0-x18/lr freely, must preserve
// x19-x28 (the compiler does). Returns 1 = deny (synthesize ENOENT), 0 =
// allow (execute the original svc). Plain C linkage (Logos emits ObjC .m,
// no mangling), so the inline-asm `bl _shdw_svc_should_deny` resolves.
__attribute__((used, noinline)) int shdw_svc_should_deny(uint64_t sysno, uint64_t a0, uint64_t a1, uint64_t a2, uintptr_t caller_lr) {
    // The patched site is in app/detector code by construction (system and
    // Shadow images are never scanned), but keep the same caller gate the
    // libc hooks use — the return address is passed explicitly because
    // isCallerExternal()'s builtin read would see the trampoline's own
    // (ShadowCore) address.
    if(!shdw_caller_is_external((const void*)caller_lr)) {
        return 0;
    }

    shdw_raw_syscall_category_t cat = shdw_raw_syscall_category((int)sysno);

    if(cat == SHADW_RAW_CAT_PATH) {
        const char* path = (const char*)a0;

        if(!path || !path[0]) {
            return 0;
        }

        // Same behavioral tripwire as the libc hooks (SHADOW_TRIP): touching
        // a JB-indicator path via raw svc is detector evidence — escalate.
        if(shdw_is_jb_probe(path)) {
            shdw_detector_detected("svc");
        }

        if(![_shadow isCPathRestricted:path]) {
            return 0;
        }

        // Natural-ENOENT rewrite: munge the buffer and let the real svc run.
        size_t moff = shdw_path_munge_offset(path);

        if(shdw_path_rewrite_enabled()
           && shdw_svc_rewriteable((int)sysno, a1)
           && moff != (size_t)-1
           && shdw_path_buf_writable(path + moff)
           && shdw_path_munge_path((char*)path)) {
            return 0;
        }

        return 1;
    }

    if(cat == SHADW_RAW_CAT_AT) {
        const char* path = (const char*)a1;

        if(!path || !path[0]) {
            return 0;
        }

        if(shdw_is_jb_probe(path)) {
            shdw_detector_detected("svc");
        }

        // Same dirfd-aware policy as the syscall(2) dispatch (sets errno on
        // denial; the trampoline ignores errno and synthesizes the raw
        // return instead).
        if(!shdw_at_path_denied((int)a0, path)) {
            return 0;
        }

        // Natural-ENOENT rewrite (openat flags live in a2, now passed by the
        // trampoline; fstatat/fstatat64 are read-only and safe).
        size_t moff = shdw_path_munge_offset(path);

        if(shdw_path_rewrite_enabled()
           && shdw_svc_rewriteable((int)sysno, a2)
           && moff != (size_t)-1
           && shdw_path_buf_writable(path + moff)
           && shdw_path_munge_path((char*)path)) {
            return 0;
        }

        return 1;
    }

    return 0;
}

// --- Naked trampolines ------------------------------------------------------
// XNU ignores svc's immediate, so one canonical trampoline handles every
// encoding. Save all caller-saved registers + x16 (syscall
// number) + lr, ask the helper, then either synthesize the ENOENT return
// (x0 = ENOENT, carry set — Darwin's kernel error convention) or restore and
// execute the original svc.
#define SHADW_SVC_TRAMPOLINE(NAME, IMM) \
__attribute__((naked, used, noinline)) static void NAME(void) { \
    __asm__ volatile( \
        "stp x0, x1, [sp, #-16]!\n" \
        "stp x2, x3, [sp, #-16]!\n" \
        "stp x4, x5, [sp, #-16]!\n" \
        "stp x6, x7, [sp, #-16]!\n" \
        "stp x8, x9, [sp, #-16]!\n" \
        "stp x10, x11, [sp, #-16]!\n" \
        "stp x12, x13, [sp, #-16]!\n" \
        "stp x14, x15, [sp, #-16]!\n" \
        "stp x16, x17, [sp, #-16]!\n" \
        "stp x18, lr, [sp, #-16]!\n" \
        /* x0 = sysno (x16), x1 = a0, x2 = a1, x3 = a2, x4 = caller lr */ \
        "mov x2, x1\n" \
        "mov x1, x0\n" \
        "mov x0, x16\n" \
        "ldr x3, [sp, #136]\n" \
        "ldr x4, [sp, #8]\n" \
        "bl _shdw_svc_should_deny\n" \
        "cbz x0, 1f\n" \
        /* deny: x0 = ENOENT, carry set (msr nzcv bit 29), keep x0 */ \
        "mov x0, #2\n" \
        "mov x1, #0x20000000\n" \
        "msr nzcv, x1\n" \
        "ldp x18, lr, [sp], #16\n" \
        "ldp x16, x17, [sp], #16\n" \
        "ldp x14, x15, [sp], #16\n" \
        "ldp x12, x13, [sp], #16\n" \
        "ldp x10, x11, [sp], #16\n" \
        "ldp x8, x9, [sp], #16\n" \
        "ldp x6, x7, [sp], #16\n" \
        "ldp x4, x5, [sp], #16\n" \
        "ldp x2, x3, [sp], #16\n" \
        "ldr x1, [sp, #8]\n" \
        "add sp, sp, #16\n" \
        "ret\n" \
        "1:\n" \
        /* allow: restore everything, execute the original svc */ \
        "ldp x18, lr, [sp], #16\n" \
        "ldp x16, x17, [sp], #16\n" \
        "ldp x14, x15, [sp], #16\n" \
        "ldp x12, x13, [sp], #16\n" \
        "ldp x10, x11, [sp], #16\n" \
        "ldp x8, x9, [sp], #16\n" \
        "ldp x6, x7, [sp], #16\n" \
        "ldp x4, x5, [sp], #16\n" \
        "ldp x2, x3, [sp], #16\n" \
        "ldp x0, x1, [sp], #16\n" \
        "svc #" IMM "\n" \
        "ret\n" \
    ); \
}

SHADW_SVC_TRAMPOLINE(shdw_svc_trampoline_80, "0x80")

// --- Scanner ----------------------------------------------------------------

#define SHDW_SVC_OPCODE_MASK 0xFFE0001FU
#define SHDW_SVC_OPCODE      0xD4000001U

static inline BOOL shdw_svc_is_instruction(uint32_t insn) {
    return (insn & SHDW_SVC_OPCODE_MASK) == SHDW_SVC_OPCODE;
}

// Images that must never be patched (see the file header: recursion safety
// and trampoline self-protection).
static BOOL shdw_svc_skip_image(const char* path) {
    if(!path || !path[0]) {
        return YES;
    }

    if(strncmp(path, "/System/", 8) == 0) {
        return YES;
    }

    if(strncmp(path, "/usr/", 5) == 0) {
        return YES;
    }

    NSString* imagePath = [NSString stringWithUTF8String:path];
    NSString* bundlePath = [NSBundle mainBundle].bundlePath;
    if([imagePath isEqualToString:bundlePath] ||
       [imagePath hasPrefix:[bundlePath stringByAppendingString:@"/"]]) {
        return NO;
    }

    // dyld reports the canonical preboot path for rootless apps while
    // NSBundle can retain /var/jb. Code inside procursus/Applications is
    // still app-owned detector code, not a bootstrap library.
    if(strstr(path, "/procursus/Applications/") != NULL) {
        return NO;
    }

    // Rootless jailbreak root: /var/jb resolves to
    // /private/preboot/<uuid>/procursus. The jailbreak's own dylibs
    // (systemhook, HKGum, libroot, ...) are NOT detector code — patching
    // their svc sites corrupts them and crashes the process.
    if(strstr(path, "/procursus/") != NULL) {
        return YES;
    }

    if(shdw_is_shadow_runtime_image(path)) {
        return YES;
    }

    return NO;
}

// Redirects one image svc site to the canonical trampoline. Idempotent: a
// patched site is a bl instruction, so a re-scan never matches it.
static _Atomic BOOL shdw_svc_far_site_seen = NO;

static void shdw_svc_try_patch_site(uintptr_t site, uint32_t insn, const char* where) {
    (void)where;
    uintptr_t target = 0;

    if(!shdw_svc_is_instruction(insn)) return;
    target = (uintptr_t)shdw_svc_trampoline_80;

    // A64 B/BL immediates are relative to the branch instruction's address.
    int64_t delta = (int64_t)target - (int64_t)site;

    if(delta < -0x8000000LL || delta > 0x7FFFFFCLL) {
        // Logging while every other thread is stopped can deadlock on a
        // runtime lock held by one of those threads. The caller reports this
        // once after the stop-the-world window instead.
        atomic_store_explicit(&shdw_svc_far_site_seen, YES, memory_order_relaxed);
        return;
    }

    *(uint32_t*)site = 0x94000000 | ((uint32_t)(delta >> 2) & 0x3FFFFFF);
    sys_icache_invalidate((void*)site, 4);
}

// All image callbacks converge here. The recursive lock handles an unusual
// same-thread callback without deadlocking; nested stop/resume pairs preserve
// the outer suspension counts.
static pthread_mutex_t shdw_svc_patch_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER;

static BOOL shdw_svc_range_has_site(uintptr_t addr, size_t size) {
    if(size < 4 || addr > UINTPTR_MAX - size) {
        return NO;
    }

    const uint32_t* words = (const uint32_t*)addr;
    size_t nwords = size / 4;

    for(size_t w = 0; w < nwords; w++) {
        if(shdw_svc_is_instruction(words[w])) {
            return YES;
        }
    }

    return NO;
}

static void shdw_svc_dispose_thread_list(thread_act_array_t threads,
                                         mach_msg_type_number_t count,
                                         mach_port_t current) {
    for(mach_msg_type_number_t i = 0; i < count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  (vm_size_t)count * sizeof(thread_t));

    if(current != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), current);
    }
}

static void shdw_svc_dispose_object(mach_port_t* object_name) {
    if(object_name && *object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), *object_name);
        *object_name = MACH_PORT_NULL;
    }
}

// Suspend exactly the threads whose thread_suspend call succeeded. This
// avoids accidentally decrementing a pre-existing suspend count if a thread
// exits between task_threads() and the loop.
static BOOL shdw_svc_suspend_others(thread_act_array_t* threads_out,
                                    mach_msg_type_number_t* count_out,
                                    mach_port_t* current_out) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    mach_port_t current = mach_thread_self();

    if(current == MACH_PORT_NULL) {
        return NO;
    }

    kern_return_t kr = task_threads(mach_task_self(), &threads, &count);

    if(kr != KERN_SUCCESS || !threads) {
        if(threads) {
            shdw_svc_dispose_thread_list(threads, count, current);
        } else {
            mach_port_deallocate(mach_task_self(), current);
        }

        return NO;
    }

    mach_msg_type_number_t suspended_through = 0;

    for(; suspended_through < count; suspended_through++) {
        if(threads[suspended_through] == current) {
            continue;
        }

        if(thread_suspend(threads[suspended_through]) != KERN_SUCCESS) {
            for(mach_msg_type_number_t i = 0; i < suspended_through; i++) {
                if(threads[i] != current) {
                    thread_resume(threads[i]);
                }
            }

            shdw_svc_dispose_thread_list(threads, count, current);
            return NO;
        }
    }

    *threads_out = threads;
    *count_out = count;
    *current_out = current;
    return YES;
}

static void shdw_svc_resume_others(thread_act_array_t threads,
                                   mach_msg_type_number_t count,
                                   mach_port_t current) {
    for(mach_msg_type_number_t i = 0; i < count; i++) {
        if(threads[i] != current) {
            thread_resume(threads[i]);
        }
    }
}

// Patch one executable range. The read-only preflight happens while other
// threads run; only the final vm_protect/write/reprotect sequence stops them.
// scan_size may be smaller than protect_size for a Mach-O __TEXT segment.
static void shdw_svc_patch_memory(uintptr_t addr, size_t scan_size,
                                  size_t protect_size, vm_prot_t original_prot,
                                  const char* where) {
    if(!shdw_svc_range_has_site(addr, scan_size)) {
        return;
    }

    pthread_mutex_lock(&shdw_svc_patch_lock);

    // Another scanner may have patched the site while this caller waited.
    if(!shdw_svc_range_has_site(addr, scan_size)) {
        pthread_mutex_unlock(&shdw_svc_patch_lock);
        return;
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    mach_port_t current = MACH_PORT_NULL;

    if(!shdw_svc_suspend_others(&threads, &thread_count, &current)) {
        pthread_mutex_unlock(&shdw_svc_patch_lock);
        return;
    }

    vm_prot_t restore_prot = original_prot;
    vm_region_basic_info_data_64_t current_info;
    mach_msg_type_number_t current_info_count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_address_t current_region = addr;
    vm_size_t current_region_size = 0;
    mach_port_t current_object = MACH_PORT_NULL;

    kern_return_t current_kr = vm_region_64(mach_task_self(), &current_region,
                                            &current_region_size,
                                            VM_REGION_BASIC_INFO_64,
                                            (vm_region_info_t)&current_info,
                                            &current_info_count, &current_object);

    if(current_object != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), current_object);
    }

    if(current_kr == KERN_SUCCESS) {
        if(!(current_info.protection & VM_PROT_EXECUTE)) {
            shdw_svc_resume_others(threads, thread_count, current);
            shdw_svc_dispose_thread_list(threads, thread_count, current);
            pthread_mutex_unlock(&shdw_svc_patch_lock);
            return;
        }

        // Re-read protection after stopping the world so a racing mprotect
        // cannot be undone by restoring stale preflight state.
        restore_prot = current_info.protection;
    }

    BOOL protected_for_write = vm_protect(mach_task_self(), addr, protect_size,
                                          FALSE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS;
    BOOL restore_failed = NO;

    if(protected_for_write) {
        uint32_t* words = (uint32_t*)addr;
        size_t nwords = scan_size / 4;

        for(size_t w = 0; w < nwords; w++) {
            uint32_t insn = words[w];

            if(shdw_svc_is_instruction(insn)) {
                shdw_svc_try_patch_site(addr + w * 4, insn, where);
            }
        }

        // Restore execute permission before any other thread can run again.
        if(vm_protect(mach_task_self(), addr, protect_size, FALSE, restore_prot) != KERN_SUCCESS) {
            restore_failed = YES;
            // Keep a failed exact restore from leaving an executable page
            // permanently non-executable. The fallback intentionally favors
            // liveness over preserving an unusual extra protection bit.
            vm_protect(mach_task_self(), addr, protect_size, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
        }
    }

    shdw_svc_resume_others(threads, thread_count, current);
    shdw_svc_dispose_thread_list(threads, thread_count, current);
    pthread_mutex_unlock(&shdw_svc_patch_lock);

    if(restore_failed) {
        NSLog(@"[Shadow][svc] protection restore failed in %s (fallback RX)", where);
    }

    if(atomic_exchange_explicit(&shdw_svc_far_site_seen, NO, memory_order_relaxed)) {
        NSLog(@"[Shadow][svc] svc site out of bl range in %s, skipped (fail soft)", where);
    }
}

// Scans one image's __TEXT for svc sites and redirects them to the matching
// trampoline. vm_protect fail-soft dance mirrors dyld.x's memory-hiding
// patch: query the original protection, add write, patch, invalidate the
// icache, restore. Idempotent: patched sites are bl instructions, so a
// re-scan never matches them.
static void shdw_svc_patch_image(const struct mach_header* mh, intptr_t slide, const char* path) {
    if(mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64) {
        return;
    }

    const struct load_command* lc = (const struct load_command*)((const char*)mh + sizeof(struct mach_header_64));

    for(uint32_t i = 0; i < mh->ncmds; i++) {
        if(lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const struct segment_command_64*)lc;

            if(strcmp(seg->segname, "__TEXT") == 0 && seg->filesize >= 4) {
                uintptr_t base = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                size_t size = seg->filesize;

                vm_region_basic_info_data_64_t info;
                mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
                vm_address_t region = base;
                vm_size_t region_size = 0;
                mach_port_t object_name = MACH_PORT_NULL;
                vm_prot_t original_prot = VM_PROT_READ | VM_PROT_EXECUTE;

                kern_return_t region_kr = vm_region_64(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_count, &object_name);
                shdw_svc_dispose_object(&object_name);

                if(region_kr == KERN_SUCCESS) {
                    original_prot = info.protection;
                }

                shdw_svc_patch_memory(base, size, seg->vmsize, original_prot, path);
                return;
            }
        }

        lc = (const struct load_command*)((const char*)lc + lc->cmdsize);
    }
}

// Add-image callback: resolve the image path (the callback only carries the
// header), apply the skip rule, scan. Registered through the REAL dyld
// registration (the dyld.x hook passes Shadow-internal callers through), so
// the registration replay covers every already-loaded image — including the
// app binary — before the app runs.
static void shdw_svc_image_add(const struct mach_header* mh, intptr_t slide) {
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        if(_dyld_get_image_header(i) == mh) {
            const char* path = _dyld_get_image_name(i);

            if(path && path[0] && !shdw_svc_skip_image(path)) {
                shdw_svc_patch_image(mh, slide, path);
            }

            return;
        }
    }
}

// Installed from the universal syscall installer, so its preference gates it (the
// unit only installs when the pref is on). Idempotent.
void shdw_svc_patch_install(void) {
    static BOOL installed = NO;

    if(installed) {
        return;
    }

    installed = YES;
    _dyld_register_func_for_add_image(shdw_svc_image_add);
}

#else   // !__arm64__

// Rootful-legacy armv7 lane: no ARM64 svc interception (arm64-only
// encoding scan; see the file header). The stub keeps syscall.x linkable.
void shdw_svc_patch_install(void) {
}

#endif  // __arm64__
