#import "hooks.h"
#import <pthread.h>
#import <mach/vm_region.h>
#import <CoreFoundation/CoreFoundation.h>

static NSMutableArray<NSDictionary *>* _shdw_dyld_collection = nil;
static NSMutableArray<NSValue *>* _shdw_dyld_add_image = nil;
static NSMutableArray<NSValue *>* _shdw_dyld_remove_image = nil;
// TLS loader-error state (plan Wave 1c): cleared at the start of each loader
// operation (dlopen/dlsym/dladdr/...), set on a Shadow denial, consumed by
// dlerror on the same thread. The old global let one thread's denial poison
// another thread's dlerror.
static _Thread_local const char* _shdw_dyld_error_tls = NULL;

// Real dyld_all_image_infos global (resolved in shadowhook_dyld). When set,
// we patch its arrays directly. When NULL (very old iOS), memory hiding stays
// off (fail soft).
static struct dyld_all_image_infos* _shdw_all_image_infos = NULL;
// TASK_DYLD_INFO returns an address that callers read after task_info returns.
// dyld may republish the real struct between that call and the first read, so
// external callers use this independently allocated filtered snapshot.
static struct dyld_all_image_infos* _shdw_task_dyld_info_mirror = NULL;
static BOOL _shdw_task_dyld_info_mirror_alloc_failed = NO;

static kern_return_t (*original_task_info)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_count);
static kern_return_t replaced_task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_count) {
    BOOL ext = isCallerExternal();
    if(ext && flavor == TASK_DYLD_INFO && target_task == mach_task_self()) {
        shdw_detector_detected("task_info");
    }
    kern_return_t kr = original_task_info(target_task, flavor, task_info_out, task_info_count);

    if(ext && kr == KERN_SUCCESS && flavor == TASK_DYLD_INFO && target_task == mach_task_self()
       && task_info_out && task_info_count && *task_info_count >= TASK_DYLD_INFO_COUNT
       && shdw_memory_hiding_enabled && _shdw_task_dyld_info_mirror) {
        task_dyld_info_data_t* info = (task_dyld_info_data_t*)task_info_out;
        if(info->all_image_info_addr == (mach_vm_address_t)(uintptr_t)_shdw_all_image_infos) {
            info->all_image_info_addr = (mach_vm_address_t)(uintptr_t)_shdw_task_dyld_info_mirror;
        }
    }

    return kr;
}

// Filtered mirrors of dyld's image info / uuid arrays: two fixed-capacity
// vm_allocate'd generation buffers each (never reallocated or freed, so the
// pointers we publish into dyld_all_image_infos stay valid forever). The
// writer fills the inactive generation under the lock and publishes it
// count-first, pointer-last — a direct reader that catches a mid-swap read
// sees the new count against the previous generation's entries, which are
// stale-but-valid within the fixed capacity, never a torn or over-read
// buffer. Two-generation publication: a reader holding a pointer across MORE
// than one rebuild may observe that generation rewritten in place — bounded
// by the fixed capacity, never an over-read. Path strings are retained in
// `_shdw_dyld_path_pool` for the lifetime of the process so their UTF8String
// pointers never dangle after a collection removal.
#define SHADOW_DYLD_MIRROR_CAPACITY 4096   // beyond any real process's image count
// ponytail: fixed buffers + warning near capacity; grow-on-demand would require
// a new vm_allocate'd generation published after a quiescent window (never-
// reallocated pointers must stay valid). Implemented warning + truncation fail-
// soft; grow path deferred until a process actually exceeds 4096.

static pthread_mutex_t _shdw_dyld_mirror_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dyld_image_info* _shdw_dyld_info_buffers[2] = {NULL, NULL};
static struct dyld_image_info* _shdw_dyld_info_published = NULL;
static struct dyld_uuid_info* _shdw_dyld_uuid_buffers[2] = {NULL, NULL};
static struct dyld_uuid_info* _shdw_dyld_uuid_published = NULL;
static NSMutableArray* _shdw_dyld_path_pool = nil;

// Ceiling for the fixed-slot private ObjC notifier registries below.  Public
// _dyld_register_func_for_{add,remove}_image registrations deliberately use
// NSMutableArray instead: dyld's public API has no eight-callback ceiling.
#define SHADOW_MAX_OBJC_NOTIFY_CBS 8

// Path-pool ceiling: entries are never freed — holders exist that outlive
// the remove path (the C4 snapshot's entry[].name pointers are handed to
// external _dyld_get_image_name callers, and the dyld_all_image_infos
// mirror's imageFilePath pointers are read raw across generation swaps), so
// the pool retains every added string for the process lifetime and is
// bounded instead — the mirror capacity, beyond any real process's image
// count (same argument as the mirror buffers above).
// ponytail: cap not refcount — freeing on remove would dangle those external
// holders; a per-string refcount registry is the upgrade if that changes.
#define SHADOW_MAX_DYLD_PATH_POOL SHADOW_DYLD_MIRROR_CAPACITY

// FIX3: per-image add/remove NSLogs gated behind this one-time-checked debug
// flag (initialized once in shadowhook_dyld — the gated callbacks can only
// fire after the registrations made there, so every check sees it set; a
// file-scope `= getenv(...)` initializer is illegal in C, and Logos .x files
// compile as Objective-C).
static bool gDyldDebug = false;

// The latest native UUID table observed before a mirror overwrite. It is kept
// for the memory-hiding escape hatch; the filtered table below is rebuilt from
// visible Mach-O headers so a newly loaded image cannot inherit stale UUIDs.
static const struct dyld_uuid_info* _shdw_real_uuid_array = NULL;
static uintptr_t _shdw_real_uuid_count = 0;

// Originals of the remaining patched struct fields, captured at FIRST patch
// time (before the first publish) so a later ON→OFF pref change can restore
// dyld's real struct exactly. Re-capturing on a later rebuild would read our
// own filtered mirrors instead of dyld's originals. Only ever touched under
// `_shdw_dyld_mirror_lock`.
static const struct dyld_image_info* _shdw_original_info_array = NULL;
static uint32_t _shdw_original_info_array_count = 0;
static uintptr_t _shdw_original_atlas_addr = 0;
static size_t _shdw_original_atlas_size = 0;
static BOOL _shdw_originals_captured = NO;

// True while the filtered mirror is published into dyld_all_image_infos.
// Tracks the patch/restore transition so a runtime ON→OFF pref change undoes
// the patch instead of leaving it applied forever (the flag is read per
// rebuild). Only ever touched under `_shdw_dyld_mirror_lock`.
static BOOL _shdw_mirror_currently_patched = NO;

// vm_protect bookkeeping shared by the patch and restore paths (both run
// under `_shdw_dyld_mirror_lock`); a failure latches here and disables both.
static BOOL _shdw_mirror_protect_failed = NO;
static vm_prot_t _shdw_mirror_original_protection = VM_PROT_READ | VM_PROT_WRITE;

// True while dyld replays the already-loaded image list through the add-image
// callback at install (see shadowhook_dyld). Each replay call would otherwise
// run a full mirror rebuild (O(N²·M) uuid compares + ~3 Mach traps per image);
// the rebuild is deferred and the single final rebuild after registration
// covers the whole collection at once.
static BOOL _shdw_dyld_replay_in_progress = NO;

// Shadow-owned image spans for shdw_caller_is_external() (see hooks.h).
// Truth is granted only to the exact installed Shadow stub, framework, and
// payload paths. Image hiding is separate: dependencies and lookalikes stay
// external callers even when their names are hidden.
// Rebuilt from the dyld image list whenever it changes and once at install;
// the writer serializes on `_shdw_own_ranges_lock` and publishes with one
// release store, so readers (no lock, one acquire load) never see a torn or
// half-built snapshot.
BOOL shdw_is_shadow_runtime_image(const char* path) {
    if(shdw_is_canonical_shadow_runtime_path(path)) {
        return YES;
    }

    NSString* root = shdw_jbroot_prefix();
    return shdw_is_canonical_shadow_runtime_path_under_root(path, root.fileSystemRepresentation) ? YES : NO;
}

shdw_own_ranges_t _shdw_own_ranges_a;
shdw_own_ranges_t _shdw_own_ranges_b;
shdw_own_ranges_t* _shdw_own_ranges_published = &_shdw_own_ranges_a;
static pthread_mutex_t _shdw_own_ranges_lock = PTHREAD_MUTEX_INITIALIZER;

// Restricted image spans (see shdw_addr_is_restricted in hooks.h). Both
// buffers start stamped with a generation the store can never publish, so
// every read falls back to -[Shadow isAddrRestricted:] until the first real
// classification lands — an unseeded table must not read as "nothing is
// restricted".
shdw_restricted_ranges_t _shdw_restricted_ranges_a = { .generation = UINT64_MAX };
shdw_restricted_ranges_t _shdw_restricted_ranges_b = { .generation = UINT64_MAX };
shdw_restricted_ranges_t* _shdw_restricted_ranges_published = &_shdw_restricted_ranges_a;
static pthread_mutex_t _shdw_restricted_ranges_lock = PTHREAD_MUTEX_INITIALIZER;

// Union span across an image's segments. Return addresses and the addresses
// the hooks classify only land inside mapped segments, so the loose union is
// exact for both range tables.
static BOOL shdw_image_span(const struct mach_header* mh, intptr_t slide, uintptr_t* outBase, uintptr_t* outEnd) {
    if(!mh || mh->magic != MH_MAGIC_64) {
        return NO;
    }

    uintptr_t base = UINTPTR_MAX, end = 0;
    const struct load_command* lc = (const void *)((const struct mach_header_64 *)mh + 1);

    for(uint32_t j = 0; j < mh->ncmds; j++) {
        if(lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* seg = (const void *)lc;
            uintptr_t s = (uintptr_t) seg->vmaddr + (uintptr_t) slide;

            if(s < base) {
                base = s;
            }

            if(s + seg->vmsize > end) {
                end = s + seg->vmsize;
            }
        }

        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }

    if(end <= base) {
        return NO;
    }

    *outBase = base;
    *outEnd = end;
    return YES;
}

// Publishes `rebuilt` into the inactive buffer. Caller holds the lock.
static void shdw_restricted_ranges_publish_locked(const shdw_restricted_ranges_t* rebuilt) {
    shdw_restricted_ranges_t* published = __atomic_load_n(&_shdw_restricted_ranges_published, __ATOMIC_ACQUIRE);
    shdw_restricted_ranges_t* other = (published == &_shdw_restricted_ranges_a) ? &_shdw_restricted_ranges_b : &_shdw_restricted_ranges_a;

    *other = *rebuilt;
    __atomic_store_n(&_shdw_restricted_ranges_published, other, __ATOMIC_RELEASE);
}

static BOOL shdw_path_is_in_main_bundle(NSString* path) {
    NSString* bundlePath = [[NSBundle mainBundle] bundlePath];
    return [path isEqualToString:bundlePath]
        || [path hasPrefix:[bundlePath stringByAppendingString:@"/"]];
}

// Classify one image path exactly the way -[Shadow isAddrRestricted:] would
// after resolving an address to it: isCPathRestricted:, the ruleset predicate.
// NOT isProtectedImagePath: — that one ORs in the Shadow-artifact basename set
// and would restrict addresses the current predicate allows.
static BOOL shdw_image_path_is_restricted(const char* path) {
    if(!path) return NO;
    NSString* imagePath = [NSString stringWithUTF8String:path];
    return !shdw_path_is_in_main_bundle(imagePath) && [_shadow isCPathRestricted:path];
}

// Full reclassification of every loaded image. Only run when the table has no
// usable verdicts — first seed, or after a ruleset reload changed what counts
// as restricted. Steady state is maintained incrementally by the add/remove
// image handlers below, so this walk is not on the per-image-event path.
static void shdw_restricted_ranges_full_rebuild(void) {
    uint64_t generation = atomic_load_explicit(&shdw_ruleset_generation, memory_order_acquire);

    shdw_restricted_ranges_t rebuilt = { .count = 0, .overflowed = 0, .generation = generation };
    uint32_t count = _dyld_image_count();

    for(uint32_t i = 0; i < count; i++) {
        if(!shdw_image_path_is_restricted(_dyld_get_image_name(i))) {
            continue;
        }

        uintptr_t base = 0, end = 0;

        if(!shdw_image_span(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), &base, &end)) {
            continue;
        }

        if(rebuilt.count >= SHADOW_RESTRICTED_IMAGE_MAX) {
            rebuilt.overflowed = 1;
            break;
        }

        rebuilt.range[rebuilt.count++] = (shdw_range_t){ .base = base, .end = end };
    }

    pthread_mutex_lock(&_shdw_restricted_ranges_lock);
    shdw_restricted_ranges_publish_locked(&rebuilt);
    pthread_mutex_unlock(&_shdw_restricted_ranges_lock);
}

// One image was mapped: classify just it and append if restricted. Idempotent
// — a full rebuild triggered by the same event may already have recorded the
// span, and the table is small enough that the dedupe scan is free.
void shdw_restricted_ranges_note_add(const struct mach_header* mh, intptr_t slide, const char* path) {
    uintptr_t base = 0, end = 0;

    if(!shdw_image_path_is_restricted(path) || !shdw_image_span(mh, slide, &base, &end)) {
        return;
    }

    pthread_mutex_lock(&_shdw_restricted_ranges_lock);

    shdw_restricted_ranges_t rebuilt = *__atomic_load_n(&_shdw_restricted_ranges_published, __ATOMIC_ACQUIRE);
    BOOL known = NO;

    for(uint32_t i = 0; i < rebuilt.count; i++) {
        if(rebuilt.range[i].base == base && rebuilt.range[i].end == end) {
            known = YES;
            break;
        }
    }

    if(!known) {
        if(rebuilt.count >= SHADOW_RESTRICTED_IMAGE_MAX) {
            rebuilt.overflowed = 1;
        } else {
            rebuilt.range[rebuilt.count++] = (shdw_range_t){ .base = base, .end = end };
        }

        shdw_restricted_ranges_publish_locked(&rebuilt);
    }

    pthread_mutex_unlock(&_shdw_restricted_ranges_lock);
}

// One image was unmapped: drop its span so a later image mapped over the same
// address does not inherit the verdict.
void shdw_restricted_ranges_note_remove(const struct mach_header* mh, intptr_t slide) {
    uintptr_t base = 0, end = 0;

    if(!shdw_image_span(mh, slide, &base, &end)) {
        return;
    }

    pthread_mutex_lock(&_shdw_restricted_ranges_lock);

    shdw_restricted_ranges_t published = *__atomic_load_n(&_shdw_restricted_ranges_published, __ATOMIC_ACQUIRE);
    shdw_restricted_ranges_t rebuilt = { .count = 0, .overflowed = published.overflowed, .generation = published.generation };

    for(uint32_t i = 0; i < published.count; i++) {
        if(published.range[i].base == base && published.range[i].end == end) {
            continue;
        }

        rebuilt.range[rebuilt.count++] = published.range[i];
    }

    if(rebuilt.count != published.count) {
        shdw_restricted_ranges_publish_locked(&rebuilt);
    }

    pthread_mutex_unlock(&_shdw_restricted_ranges_lock);
}

void shdw_own_ranges_refresh(void) {
    // Replay guard: during shadowhook_dyld's add-image registration, dyld
    // synchronously replays EVERY loaded image, and each replay callback
    // calls this refresh, which scans the WHOLE image list through the full
    // restriction engine (isProtectedImagePath: → RulesetStore.currentSnapshot
    // → @synchronized). N callbacks × N-image scans = O(N²) CPU churn — a
    // launch watchdog kill on image-heavy apps (observed on-device:
    // ConsumerApp, 20s budget exhausted, 27.6s CPU, spin in objc_sync_exit).
    // The single final refresh after registration (shadowhook_dyld) rebuilds
    // the same spans once, so skipping during replay loses nothing.
    if(_shdw_dyld_replay_in_progress) {
        return;
    }

    // Post-replay, this runs from every add/remove-image callback and walks
    // the WHOLE image list each time — O(N²) across a launch that loads N
    // images, which is the same shape as the replay problem above, just
    // spread out. The set it collects can only change when a SHADOW-owned
    // image is mapped or unmapped, and those all load during the ctor; an
    // app's own dlopens can never add one. So let the caller tell us whether
    // this event could possibly matter, and skip the walk when it cannot.
    // shdw_own_ranges_refresh_if_relevant below is that filter.
    pthread_mutex_lock(&_shdw_own_ranges_lock);

    shdw_own_ranges_t* published = __atomic_load_n(&_shdw_own_ranges_published, __ATOMIC_ACQUIRE);
    shdw_own_ranges_t* other = (published == &_shdw_own_ranges_a) ? &_shdw_own_ranges_b : &_shdw_own_ranges_a;

    shdw_own_ranges_t rebuilt = { .count = 0 };

    uint32_t count = _dyld_image_count();

    for(uint32_t i = 0; i < count && rebuilt.count < SHADOW_OWN_IMAGE_MAX; i++) {
        const char* path = _dyld_get_image_name(i);

        // Collect only exact installed Shadow images. The own spans are few
        // and fixed once loaded; never use the broader image-hiding policy.
        if(!path || !shdw_is_shadow_runtime_image(path)) {
            continue;
        }

        uintptr_t base = 0, end = 0;

        if(shdw_image_span(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), &base, &end)) {
            rebuilt.range[rebuilt.count++] = (shdw_range_t){ .base = base, .end = end };
        }
    }

    *other = rebuilt;
    __atomic_store_n(&_shdw_own_ranges_published, other, __ATOMIC_RELEASE);

    pthread_mutex_unlock(&_shdw_own_ranges_lock);

    // The restricted-span table is maintained incrementally by the add/remove
    // image handlers, so it needs a full reclassification only when its
    // verdicts no longer apply: the first refresh after install (unseeded), or
    // a ruleset reload since the last classification.
    //
    // ponytail: a reload with no subsequent image event leaves readers on the
    // slow path until the next dlopen — correct, just uncached, and identical
    // to the behaviour before this table existed. If that window ever matters,
    // have RulesetStore's reload call this directly instead of waiting.
    if(__atomic_load_n(&_shdw_restricted_ranges_published, __ATOMIC_ACQUIRE)->generation
        != atomic_load_explicit(&shdw_ruleset_generation, memory_order_acquire)) {
        shdw_restricted_ranges_full_rebuild();
    }
}

// Per-image-event entry point: refresh only when this image could change what
// the tables hold. `path` is the image being mapped or unmapped.
//
// The own-ranges set is Shadow's own artifacts, matched by the cheap
// exact-name predicate — one strrchr plus a handful of strncmps, versus a walk
// of every loaded image. The restricted table still needs the generation check
// on every event (a ruleset reload has no image event of its own), but that is
// two atomic loads.
static void shdw_own_ranges_refresh_if_relevant(const char* path) {
    if(path && !shdw_is_shadow_runtime_image(path)
        && __atomic_load_n(&_shdw_restricted_ranges_published, __ATOMIC_ACQUIRE)->generation
            == atomic_load_explicit(&shdw_ruleset_generation, memory_order_acquire)) {
        return;
    }

    shdw_own_ranges_refresh();
}

// C4: immutable snapshot of the collection for the hot dyld enumeration
// accessors. Two fixed-capacity vm_allocate'd buffers (never freed or
// reallocated, so the published pointer can't dangle); the writer fills the
// inactive buffer under the lock and publishes it. Readers take the same
// lock (see shdw_dyld_snapshot_begin), so a read can never observe a torn or
// mismatched entry. `name` pointers come from `_shdw_dyld_path_pool`, which
// retains every path string for the process lifetime, so they never dangle.
typedef struct {
    uint32_t count;
    struct {
        struct mach_header* mh;
        intptr_t slide;
        const char* name;
    } entry[SHADOW_DYLD_MIRROR_CAPACITY];
} shdw_dyld_snapshot_t;

static shdw_dyld_snapshot_t* _shdw_dyld_snapshot = NULL;
static shdw_dyld_snapshot_t* _shdw_dyld_snapshot_buffers[2] = {NULL, NULL};

// The dyld_all_image_infos patch (plan Wave 1c) is UNCONDITIONAL when the
// struct exists: the old "MemoryLevelHiding" pref gate left the real arrays
// readable by any untrusted caller (task_info TASK_DYLD_INFO /
// _dyld_get_all_image_infos read this struct directly, bypassing the dyld
// API filter), so the filtered mirror must always be published. The pref is
// now a no-op by design.

static void shadowhook_dyld_rebuild_dyldinfo(void);

// dyld publishes a fresh real infoArray after its add/remove callbacks, then
// calls this debugger notification. Re-apply the mirror at that stable point
// so the live TASK_DYLD_INFO struct cannot be overwritten by the same load.
static void (*original_dyld_image_notification)(enum dyld_image_mode mode, uint32_t infoCount, const struct dyld_image_info info[]);
static void replaced_dyld_image_notification(enum dyld_image_mode mode, uint32_t infoCount, const struct dyld_image_info info[]) {
    shadowhook_dyld_rebuild_dyldinfo();
    original_dyld_image_notification(mode, infoCount, info);
}

// todo: maybe hook this private symbol
// extern void call_funcs_for_add_image(struct mach_header *mh, unsigned long vmaddr_slide);

// Locked snapshot access for the hot accessors: the snapshot is rebuilt
// under `_shdw_dyld_mirror_lock`, so reading it under the same lock can
// never observe a torn or mismatched entry (an uncontended unfair lock is a
// few ns — nothing compared to the array copies this replaced). Returns NULL
// when no snapshot has ever been published (allocation failed); callers then
// fall back to the old collection path.
static shdw_dyld_snapshot_t* shdw_dyld_snapshot_begin(void) {
    pthread_mutex_lock(&_shdw_dyld_mirror_lock);
    return _shdw_dyld_snapshot;
}

static void shdw_dyld_snapshot_end(void) {
    pthread_mutex_unlock(&_shdw_dyld_mirror_lock);
}

static uint32_t (*original_dyld_image_count)();
static uint32_t replaced_dyld_image_count() {
    // C0-2: Shadow's own code (and internal scopes) sees truth; every other
    // caller — app, detector, system framework — sees the filtered snapshot.
    if(!isCallerExternal()) {
        return original_dyld_image_count();
    }

    shdw_dyld_snapshot_t* snapshot = shdw_dyld_snapshot_begin();

    if(!snapshot) {
        NSArray* collection = [_shdw_dyld_collection copy];
        shdw_dyld_snapshot_end();
        return (uint32_t) [collection count];
    }

    uint32_t count = snapshot->count;
    shdw_dyld_snapshot_end();
    return count;
}

static const struct mach_header* (*original_dyld_get_image_header)(uint32_t image_index);
static const struct mach_header* replaced_dyld_get_image_header(uint32_t image_index) {
    if(!isCallerExternal()) {
        return original_dyld_get_image_header(image_index);
    }

    shdw_dyld_snapshot_t* snapshot = shdw_dyld_snapshot_begin();

    if(!snapshot) {
        NSArray* collection = [_shdw_dyld_collection copy];
        shdw_dyld_snapshot_end();
        return image_index < [collection count] ? (struct mach_header *)[collection[image_index][@"mach_header"] pointerValue] : NULL;
    }

    const struct mach_header* header = image_index < snapshot->count ? snapshot->entry[image_index].mh : NULL;
    shdw_dyld_snapshot_end();
    return header;
}

static intptr_t (*original_dyld_get_image_vmaddr_slide)(uint32_t image_index);
static intptr_t replaced_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    if(!isCallerExternal()) {
        return original_dyld_get_image_vmaddr_slide(image_index);
    }

    shdw_dyld_snapshot_t* snapshot = shdw_dyld_snapshot_begin();

    if(!snapshot) {
        NSArray* collection = [_shdw_dyld_collection copy];
        shdw_dyld_snapshot_end();
        return image_index < [collection count] ? (intptr_t)[collection[image_index][@"slide"] pointerValue] : 0;
    }

    intptr_t slide = image_index < snapshot->count ? snapshot->entry[image_index].slide : 0;
    shdw_dyld_snapshot_end();
    return slide;
}

static const char* (*original_dyld_get_image_name)(uint32_t image_index);
static const char* replaced_dyld_get_image_name(uint32_t image_index) {
    if(!isCallerExternal()) {
        return original_dyld_get_image_name(image_index);
    }

    shdw_dyld_snapshot_t* snapshot = shdw_dyld_snapshot_begin();

    if(!snapshot) {
        NSArray* collection = [_shdw_dyld_collection copy];
        shdw_dyld_snapshot_end();

        if(image_index < [collection count]) {
            const char* name = [collection[image_index][@"name"] fileSystemRepresentation];

            if(name) {
                // The pointer dangles once the pool drains; copy into
                // thread-local storage (use-immediately contract, same as the
                // getenv PATH sanitizer).
                static _Thread_local char buf[PATH_MAX];
                strlcpy(buf, name, sizeof(buf));
                return buf;
            }
        }

        return NULL;
    }

    const char* name = image_index < snapshot->count ? snapshot->entry[image_index].name : NULL;
    shdw_dyld_snapshot_end();
    return name;
}

// _dyld_image_path_containing_address is called directly by commercial
// detection SDKs (bypasses dyld API filtering) AND by Shadow's own Core.m
// (isAddrExternal/isAddrRestricted). Return truth to Shadow's own callers
// (C0-2: only Shadow-owned images / internal scopes), lie (NULL for
// restricted, see the item-7 refinement below) to everyone else.
// The reentrancy flag is _Thread_local because the only recursion here is
// same-thread (this hook → isCPathRestricted → isPathRestricted, guarded by
// the flag) — per-thread scope is exactly right and needs no lock.
static _Thread_local BOOL _shdw_dyipca_in_hook = NO;

static const char* (*original_dyld_image_path_containing_address)(const void* addr);
static const char* replaced_dyld_image_path_containing_address(const void* addr) {
    if(_shdw_dyipca_in_hook || !addr) {
        return original_dyld_image_path_containing_address(addr);
    }

    _shdw_dyipca_in_hook = YES;

    // Is the CALLER of this hook inside Shadow? (not the addr arg)
    BOOL caller_is_external = shdw_caller_is_external(__builtin_return_address(0));

    _shdw_dyipca_in_hook = NO;

    if(!caller_is_external) {
        return original_dyld_image_path_containing_address(addr);
    }

    const char* result = original_dyld_image_path_containing_address(addr);

    if(!result) {
        return NULL;
    }

    // Restricted address: report "in no image" (NULL) — the executable-path
    // fake was a contradiction a detector could fingerprint (plan Wave 1c).
    if([_shadow isProtectedImagePath:@(result)]) {
        return NULL;
    }

    return result;
}

// _dyld_get_image_header_containing_address / dyld_image_header_containing_address:
// same leak as the path variant — resolves an address back to its owning image
// header, which would expose a filtered dylib even though it's gone from every
// enumeration API. Same pattern as above; unlike the path variant there is no
// plausible fake header, so restricted images resolve to "not in any image"
// (NULL) — the same signal dyld itself returns for unmapped addresses.
static _Thread_local BOOL _shdw_dyighca_in_hook = NO;

static const struct mach_header* (*original_dyld_image_header_containing_address)(const void* addr);
static const struct mach_header* replaced_dyld_image_header_containing_address(const void* addr) {
    if(_shdw_dyighca_in_hook || !addr) {
        return original_dyld_image_header_containing_address(addr);
    }

    _shdw_dyighca_in_hook = YES;

    // Is the CALLER of this hook inside Shadow (own code sees truth)? Not
    // the addr arg. Every other caller — app code, embedded detectors,
    // system frameworks — gets the filtered answer.
    BOOL caller_is_external = shdw_caller_is_external(__builtin_return_address(0));

    _shdw_dyighca_in_hook = NO;

    if(!caller_is_external) {
        return original_dyld_image_header_containing_address(addr);
    }

    // External caller probing a filtered image's address: report no image.
    if(shdw_addr_is_restricted(addr)) {
        return NULL;
    }

    return original_dyld_image_header_containing_address(addr);
}

// The exported _dyld_get_image_header_containing_address alias (dyld4,
// iOS 15+) leaks exactly like dyld_image_header_containing_address; hook it
// with the same replacement. Its own original slot is unused — the body
// resolves through the direct-linked symbol's original.
static const struct mach_header* (*original_dyld_get_image_header_containing_address)(const void* addr);

// --- Address-attribution siblings (plan Wave 1c): every dyld SPI that maps
// an address or header back to an image must answer "unknown" for protected
// images — header, uuid, install name, unwind sections, slide.

static intptr_t (*original_dyld_get_image_slide)(const struct mach_header* mh);
static intptr_t replaced_dyld_get_image_slide(const struct mach_header* mh) {
    if(!isCallerExternal()) {
        return original_dyld_get_image_slide(mh);
    }

    if(!mh || shdw_addr_is_restricted(mh)) {
        return 0;
    }

    return original_dyld_get_image_slide(mh);
}

static bool (*original_dyld_get_image_uuid)(const struct mach_header* mh, uuid_t uuid);
static bool replaced_dyld_get_image_uuid(const struct mach_header* mh, uuid_t uuid) {
    if(!isCallerExternal()) {
        return original_dyld_get_image_uuid(mh, uuid);
    }

    if(!mh || shdw_addr_is_restricted(mh)) {
        if(uuid) {
            memset(uuid, 0, sizeof(uuid_t));
        }

        return false;
    }

    return original_dyld_get_image_uuid(mh, uuid);
}

// Private libdyld export (dyld3/dyld4); resolved at install via findSymbolInImage:
extern const char* dyld_image_get_installname(const struct mach_header* mh);
static const char* (*original_dyld_image_get_installname)(const struct mach_header* mh);
static const char* replaced_dyld_image_get_installname(const struct mach_header* mh) {
    if(!isCallerExternal()) {
        return original_dyld_image_get_installname(mh);
    }

    if(!mh || shdw_addr_is_restricted(mh)) {
        return NULL;
    }

    return original_dyld_image_get_installname(mh);
}

static bool (*original_dyld_find_unwind_sections)(void* addr, struct dyld_unwind_sections* info);
static bool replaced_dyld_find_unwind_sections(void* addr, struct dyld_unwind_sections* info) {
    if(!isCallerExternal()) {
        return original_dyld_find_unwind_sections(addr, info);
    }

    if(!addr || shdw_addr_is_restricted(addr)) {
        if(info) {
            memset(info, 0, sizeof(struct dyld_unwind_sections));
        }

        return false;
    }

    return original_dyld_find_unwind_sections(addr, info);
}

// dlopen family resolution (plan Wave 3): expand @executable_path,
// @loader_path and caller LC_RPATH entries into concrete candidates, then
// deny when any candidate resolves to a protected path. Bare relative paths
// resolve against the process CWD. The old synthetic /var/jb/usr/lib
// working-dir + automatic .dylib suffix behaviors are gone — the real
// resolution is classified instead. `callerAddr` is the image that issued the
// dlopen (the explicit caller argument of dlopen_from/dlopen_internal, or the
// hook's own return address for public dlopen).
static void shdw_dlopen_add_rpath_candidates(NSString* rest, const struct mach_header* mh, NSMutableArray* candidates) {
    if(!mh || mh->magic != MH_MAGIC_64 || !rest) {
        return;
    }

    const struct load_command* lc = (const void *)((const struct mach_header_64 *)mh + 1);

    for(uint32_t j = 0; j < mh->ncmds; j++) {
        if(lc->cmd == LC_RPATH) {
            const struct rpath_command* rp = (const void *)lc;
            const char* rpath = (const char *)lc + rp->path.offset;

            if(rpath && rpath[0]) {
                NSString* rpStr = [NSString stringWithUTF8String:rpath];

                // Nested tokens inside an rpath entry (rare): expand them too.
                if([rpStr hasPrefix:@"@executable_path/"]) {
                    NSString* execDir = [[[NSBundle mainBundle] executablePath] stringByDeletingLastPathComponent];

                    if(execDir) {
                        rpStr = [execDir stringByAppendingPathComponent:[rpStr substringFromIndex:[@"@executable_path/" length]]];
                    }
                } else if([rpStr hasPrefix:@"@loader_path/"]) {
                    const char* mhPath = dyld_image_path_containing_address(mh);

                    if(mhPath) {
                        NSString* dir = [[NSString stringWithUTF8String:mhPath] stringByDeletingLastPathComponent];
                        rpStr = [dir stringByAppendingPathComponent:[rpStr substringFromIndex:[@"@loader_path/" length]]];
                    }
                }

                [candidates addObject:[rpStr stringByAppendingPathComponent:rest]];
            }
        }

        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
}

static BOOL shdw_dlopen_resolution_denied(const char* path, const void* callerAddr) {
    if(!path || !path[0]) {
        return NO;
    }

    NSString* p = [NSString stringWithUTF8String:path];
    NSMutableArray* candidates = [NSMutableArray array];

    if([p hasPrefix:@"@executable_path/"]) {
        NSString* execDir = [[[NSBundle mainBundle] executablePath] stringByDeletingLastPathComponent];

        if(execDir) {
            [candidates addObject:[execDir stringByAppendingPathComponent:[p substringFromIndex:[@"@executable_path/" length]]]];
        }
    } else if([p hasPrefix:@"@loader_path/"]) {
        const char* callerPath = callerAddr ? dyld_image_path_containing_address(callerAddr) : NULL;

        if(callerPath) {
            NSString* dir = [[NSString stringWithUTF8String:callerPath] stringByDeletingLastPathComponent];
            [candidates addObject:[dir stringByAppendingPathComponent:[p substringFromIndex:[@"@loader_path/" length]]]];
        }
    } else if([p hasPrefix:@"@rpath/"]) {
        NSString* rest = [p substringFromIndex:[@"@rpath/" length]];
        const struct mach_header* callerMH = callerAddr ? dyld_image_header_containing_address(callerAddr) : NULL;

        shdw_dlopen_add_rpath_candidates(rest, callerMH, candidates);
    } else if([p hasPrefix:@"@"]) {
        // Unknown token: dyld fails the load naturally; nothing to protect.
        return NO;
    } else if([p hasPrefix:@"/"]) {
        [candidates addObject:p];
    } else {
        // Bare relative path: resolve against the process CWD.
        NSString* cwd = [[NSFileManager defaultManager] currentDirectoryPath];

        if(cwd) {
            [candidates addObject:[cwd stringByAppendingPathComponent:p]];
        }
    }

    for(NSString* candidate in candidates) {
        if(shdw_path_is_in_main_bundle(candidate)) {
            continue;
        }

        if([_shadow isPathRestricted:candidate options:@{kShadowRestrictionEnableResolve : @(NO)}] || [_shadow isProtectedImagePath:candidate]) {
            return YES;
        }
    }

    return NO;
}

static void* (*original_dlopen)(const char* path, int mode);
static void* replaced_dlopen(const char* path, int mode) {
    // Each loader operation clears the thread's error state up front.
    _shdw_dyld_error_tls = NULL;

    if(!isCallerExternal() || !path) {
        return original_dlopen(path, mode);
    }

    if(shdw_dlopen_resolution_denied(path, __builtin_extract_return_addr(__builtin_return_address(0)))) {
        // A non-tweak caller trying to dlopen a jailbreak dylib is a probe.
        shdw_detector_detected("dlopen");

        _shdw_dyld_error_tls = "library not found";
        return NULL;
    }

    return original_dlopen(path, mode);
}

static void* (*original_dlopen_internal)(const char* path, int mode, void* caller);
static void* replaced_dlopen_internal(const char* path, int mode, void* caller) {
    _shdw_dyld_error_tls = NULL;

    if(!isCallerExternal() || !path) {
        return original_dlopen_internal(path, mode, caller);
    }

    // dlopen_from/dlopen_internal carry the true caller image explicitly;
    // @loader_path/@rpath resolve against it.
    if(shdw_dlopen_resolution_denied(path, caller)) {
        shdw_detector_detected("dlopen");

        _shdw_dyld_error_tls = "library not found";
        return NULL;
    }

    return original_dlopen_internal(path, mode, caller);
}

static bool (*original_dlopen_preflight)(const char* path);
static bool replaced_dlopen_preflight(const char* path) {
    _shdw_dyld_error_tls = NULL;

    if(!isCallerExternal() || !path) {
        return original_dlopen_preflight(path);
    }

    if(shdw_dlopen_resolution_denied(path, __builtin_extract_return_addr(__builtin_return_address(0)))) {
        shdw_detector_detected("dlopen");

        return false;
    }

    return original_dlopen_preflight(path);
}

static void (*original_dyld_register_func_for_add_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    // C0-2: Shadow's own registrations (none post-install today) pass
    // through; everyone else registers with the filtered replay.
    if(!isCallerExternal() || !func) {
        return original_dyld_register_func_for_add_image(func);
    }

    [_shdw_dyld_add_image addObject:[NSValue valueWithPointer:func]];

    // do initial call
    NSArray* _dyld_collection = [_shdw_dyld_collection copy];

    if(_dyld_collection) {
        for(NSDictionary* dylib in _dyld_collection) {
            func((struct mach_header *)[dylib[@"mach_header"] pointerValue], (intptr_t)[dylib[@"slide"] pointerValue]);
        }
    }
}

static void (*original_dyld_register_func_for_remove_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_remove_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if(!isCallerExternal() || !func) {
        return original_dyld_register_func_for_remove_image(func);
    }

    [_shdw_dyld_remove_image addObject:[NSValue valueWithPointer:func]];
}

// Format buffer for TLS loader-error messages carrying a symbol name
// (dlsym denials answer "symbol not found: <name>", the stock dlsym shape —
// dlopen's "library not found" for a dlsym denial would fingerprint the
// hook to a detector that parses dlerror text).
static _Thread_local char _shdw_dyld_error_msg[512];

static void shdw_dyld_set_error(const char* fmt, const char* arg) {
    if(arg) {
        snprintf(_shdw_dyld_error_msg, sizeof(_shdw_dyld_error_msg), fmt, arg);
        _shdw_dyld_error_tls = _shdw_dyld_error_msg;
    } else {
        _shdw_dyld_error_tls = fmt;
    }
}

void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!mh) {
        return;
    }

    const char* image_path = dyld_image_path_containing_address(mh);

    // The dyld image list changed: refresh the app-bundle spans, if this image
    // is one that can change them.
    shdw_own_ranges_refresh_if_relevant(image_path);

    // Add if safe dylib. Same policy for every image — no blanket /System
    // admission (plan Wave 1c): a protected artifact installed under /System
    // must not leak into the visible snapshot via the path prefix. The
    // protected-name predicate also catches Shadow's own artifacts that the
    // ruleset may not cover.
    if(image_path) {
        NSString* path = [NSString stringWithUTF8String:image_path];

        // isProtectedImagePath: is isCPathRestricted: OR the Shadow-artifact
        // basename set, so a NO here is a NO for the restricted-span table
        // too. Asking once and reusing the answer keeps an ordinary system
        // image at two engine queries per load instead of three — and the
        // overwhelming majority of the images an app loads are ordinary.
        BOOL ownImage = shdw_path_is_in_main_bundle(path);
        BOOL protectedImage = !ownImage && (shdw_is_shadow_runtime_image(image_path)
            || [_shadow isProtectedImagePath:path]);

        // Record the span if this image is restricted, so the address-keyed
        // hooks can answer from the range table instead of re-resolving and
        // re-judging this path on every intercepted call (see
        // shdw_addr_is_restricted).
        if(protectedImage) {
            shdw_restricted_ranges_note_add(mh, vmaddr_slide, image_path);
        }

        if(!protectedImage && (ownImage
            || ![_shadow isPathRestricted:path options:@{kShadowRestrictionEnableResolve : @(NO)}])) {
            if(gDyldDebug) {
                NSLog(@"%@: %@: %@", @"dyld", @"adding lib", path);
            }

            [_shdw_dyld_collection addObject:@{
                @"name" : path,
                @"mach_header" : [NSValue valueWithPointer:mh],
                @"slide" : [NSValue valueWithPointer:(void *)vmaddr_slide]
            }];

            // Retain the path for the mirror's imageFilePath pointers (the
            // collection may release it again on remove). Capped at
            // SHADOW_MAX_DYLD_PATH_POOL: beyond the ceiling the string is
            // not retained past removal (never reached in practice).
            if([_shdw_dyld_path_pool count] < SHADOW_MAX_DYLD_PATH_POOL) {
                [_shdw_dyld_path_pool addObject:path];
            }

            // Keep dyld_all_image_infos filtered arrays in sync. Deferred
            // during the add-image replay at install — one rebuild after
            // registration covers the whole collection.
            if(!_shdw_dyld_replay_in_progress) {
                shadowhook_dyld_rebuild_dyldinfo();
            }

            // Call event handlers.
            NSArray* _dyld_add_image = [_shdw_dyld_add_image copy];

            if([_dyld_add_image count]) {
                NSLog(@"dyld: add_image calling handlers");

                for(NSValue* func_ptr in _dyld_add_image) {
                    void (*func)(const struct mach_header*, intptr_t) = [func_ptr pointerValue];
                    func(mh, vmaddr_slide);
                }
            }
        } else if(!_shdw_dyld_replay_in_progress) {
            // dyld republishes its real arrays for every load. Re-apply our
            // unchanged filtered collection when the new image is hidden too.
            shadowhook_dyld_rebuild_dyldinfo();
        }
    }
}

// Forward decl: ObjC unmapped-notifier fan-out (defined with the notifier
// machinery near the load-callback section); the remove-image handler drives
// it for visible removals.
static void shdw_objc_notify_unmapped(const char* path, const struct mach_header* mh);

void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!mh) {
        return;
    }

    // The dyld image list changed: refresh the app-bundle spans, if this image
    // is one that can change them. On the remove path the image is already
    // unmapped, so resolve its path before anything else touches dyld.
    shdw_own_ranges_refresh_if_relevant(dyld_image_path_containing_address(mh));

    // Drop the unmapped image's restricted span before anything can be mapped
    // over the same addresses. Unconditional: the span is dropped by address,
    // so it costs one scan of a tiny table and never re-asks the engine.
    shdw_restricted_ranges_note_remove(mh, vmaddr_slide);

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    NSDictionary* dylibToRemove = nil;

    for(NSDictionary* dylib in _dyld_collection) {
        if((struct mach_header *)[dylib[@"mach_header"] pointerValue] == mh) {
            // Don't remove while in enumeration, store for later
            dylibToRemove = dylib;
            break;
        }
    }

    if(dylibToRemove) {
        // Remove this from our collection
        if(gDyldDebug) {
            NSLog(@"%@: %@: %@", @"dyld", @"removing lib", dylibToRemove[@"name"]);
        }
        [_shdw_dyld_collection removeObject:dylibToRemove];

        // Keep dyld_all_image_infos filtered arrays in sync.
        shadowhook_dyld_rebuild_dyldinfo();

        // Call event handlers.
        NSArray* _dyld_remove_image = [_shdw_dyld_remove_image copy];

        if([_dyld_remove_image count]) {
            NSLog(@"dyld: remove_image calling handlers");
            
            for(NSValue* func_ptr in _dyld_remove_image) {
                void (*func)(const struct mach_header*, intptr_t) = [func_ptr pointerValue];
                func(mh, vmaddr_slide);
            }
        }

        // ObjC unmapped-notifier fan-out: the image was in the collection
        // (visible), so its removal is reported — hidden images were never
        // mapped to registrants and never reach this path.
        shdw_objc_notify_unmapped([dylibToRemove[@"name"] fileSystemRepresentation], mh);
    }
}

static char* (*original_dlerror)(void);
static char* replaced_dlerror(void) {
    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_dlerror();
    }

    // Consume the thread's Shadow-denial error; otherwise report libdyld's
    // own (real) error state.
    if(_shdw_dyld_error_tls) {
        const char* message = _shdw_dyld_error_tls;
        _shdw_dyld_error_tls = NULL;
        return (char *)message;
    }

    return original_dlerror();
}

// Symbol policy table (plan Wave 1c): hooked system APIs resolve to Shadow's
// REPLACEMENT for external callers — never the un-hooked original — so the
// fishhook rebind bypass (dlsym of a rebindable export, explicit libdyld
// handles, RTLD_NEXT end-runs) dies here. Keyed by exported symbol name;
// matched before any handle-based resolution, for every handle kind.
typedef struct {
    const char* name;
    void* replacement;
} shdw_sym_policy_entry_t;

// Forward decls for the table entries defined below.
static void replaced_dyld_images_for_addresses(unsigned count, const void* addresses[], struct dyld_image_uuid_offset infos[]);
static void replaced_dyld_register_for_image_loads(void (*func)(const struct mach_header* mh, const char* path, bool unloadable));
static void replaced_dyld_register_for_bulk_image_loads(void (*func)(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]));
static void* replaced_dlsym(void* handle, const char* symbol);
static int replaced_dladdr(const void* addr, Dl_info* info);

// dyld_process_state values (dyld_process_info.h is macOS-only; the ABI is a
// plain enum — not_started=0, running=1, done=2). Defined here, before the
// table, so the process-info prototypes below can use it; the hooks that
// return it live in the process-snapshot section.
typedef enum {
    shdw_dyld_process_state_not_started = 0,
    shdw_dyld_process_state_running = 1,
    shdw_dyld_process_state_done = 2
} shdw_dyld_process_state_t;

// File-scope tags for the process-snapshot types (typedef'd in the
// process-snapshot section below); a prototype-scoped tag would be a
// different type from the definition's file-scope one.
struct _dyld_process_info;
struct shdw_dyld_process_info_image;

// Process-snapshot family (opaque handles — see the section below).
static struct _dyld_process_info* replaced_dyld_process_info_create(task_t task, uint64_t timestamp, uint32_t* returnCount);
static shdw_dyld_process_state_t replaced_dyld_process_info_get_state(struct _dyld_process_info* info);
static void replaced_dyld_process_info_get_images(struct _dyld_process_info* info, struct shdw_dyld_process_info_image* images, uint32_t* infoCount);
static void replaced_dyld_process_info_get_image_path(struct _dyld_process_info* info, struct shdw_dyld_process_info_image* image, char* buffer, uint32_t bufferSize);
static void replaced_dyld_process_info_get_image_uuid(struct _dyld_process_info* info, struct shdw_dyld_process_info_image* image, uuid_t uuid);
static void replaced_dyld_process_info_destroy(struct _dyld_process_info* info);
static void replaced_dyld_process_info_release(struct _dyld_process_info* info);

// ObjC-mapped notifier family (slot-array fan-out — see the section below).
static void replaced_dyld_objc_notify_register(_dyld_objc_notify_mapped mapped, _dyld_objc_notify_init init, _dyld_objc_notify_unmapped unmapped);
static void replaced_objc_addLoadImageFunc(void (*func)(const struct mach_header* mh));

// Legacy NS* lookup family (macOS-era exports, resolved by name at install).
static const struct mach_header* replaced_NSAddImage(const char* image_name, uint32_t options);
static void* replaced_NSLookupSymbolInImage(const struct mach_header* image, const char* symbolName, uint32_t options);
static int32_t replaced_NSVersionOfRunTimeLibrary(const char* libraryName);

// Sorted by name (strcmp order) for bsearch — keep it sorted when adding
// entries, or lookups silently miss.
static const shdw_sym_policy_entry_t shdw_sym_policy_table[] = {
    { "NSAddImage", (void *)&replaced_NSAddImage },
    { "NSLookupSymbolInImage", (void *)&replaced_NSLookupSymbolInImage },
    { "NSVersionOfRunTimeLibrary", (void *)&replaced_NSVersionOfRunTimeLibrary },
    { "_dyld_find_unwind_sections", (void *)&replaced_dyld_find_unwind_sections },
    { "_dyld_get_image_header", (void *)&replaced_dyld_get_image_header },
    { "_dyld_get_image_header_containing_address", (void *)&replaced_dyld_image_header_containing_address },
    { "_dyld_get_image_name", (void *)&replaced_dyld_get_image_name },
    { "_dyld_get_image_slide", (void *)&replaced_dyld_get_image_slide },
    { "_dyld_get_image_uuid", (void *)&replaced_dyld_get_image_uuid },
    { "_dyld_get_image_vmaddr_slide", (void *)&replaced_dyld_get_image_vmaddr_slide },
    { "_dyld_image_count", (void *)&replaced_dyld_image_count },
    { "_dyld_images_for_addresses", (void *)&replaced_dyld_images_for_addresses },
    { "_dyld_objc_notify_register", (void *)&replaced_dyld_objc_notify_register },
    { "_dyld_process_info_create", (void *)&replaced_dyld_process_info_create },
    { "_dyld_process_info_destroy", (void *)&replaced_dyld_process_info_destroy },
    { "_dyld_process_info_get_image_path", (void *)&replaced_dyld_process_info_get_image_path },
    { "_dyld_process_info_get_image_uuid", (void *)&replaced_dyld_process_info_get_image_uuid },
    { "_dyld_process_info_get_images", (void *)&replaced_dyld_process_info_get_images },
    { "_dyld_process_info_get_state", (void *)&replaced_dyld_process_info_get_state },
    { "_dyld_process_info_release", (void *)&replaced_dyld_process_info_release },
    { "_dyld_register_for_bulk_image_loads", (void *)&replaced_dyld_register_for_bulk_image_loads },
    { "_dyld_register_for_image_loads", (void *)&replaced_dyld_register_for_image_loads },
    { "_dyld_register_func_for_add_image", (void *)&replaced_dyld_register_func_for_add_image },
    { "_dyld_register_func_for_remove_image", (void *)&replaced_dyld_register_func_for_remove_image },
    { "dladdr", (void *)&replaced_dladdr },
    { "dlerror", (void *)&replaced_dlerror },
    { "dlopen", (void *)&replaced_dlopen },
    { "dlopen_preflight", (void *)&replaced_dlopen_preflight },
    { "dlsym", (void *)&replaced_dlsym },
    { "dyld_image_get_installname", (void *)&replaced_dyld_image_get_installname },
    { "dyld_image_header_containing_address", (void *)&replaced_dyld_image_header_containing_address },
    { "dyld_image_path_containing_address", (void *)&replaced_dyld_image_path_containing_address },
    { "objc_addLoadImageFunc", (void *)&replaced_objc_addLoadImageFunc },
    { "task_info", (void *)&replaced_task_info },
};
#define SHADOW_SYM_POLICY_COUNT (sizeof(shdw_sym_policy_table) / sizeof(shdw_sym_policy_table[0]))

// bsearch comparator for the policy table above; the key's replacement
// field is unused.
static int shdw_sym_policy_compare(const void* a, const void* b) {
    return strcmp(((const shdw_sym_policy_entry_t *)a)->name, ((const shdw_sym_policy_entry_t *)b)->name);
}

// Index of the image containing `addr` in dyld's load order, or -1.
static int shdw_image_index_of(const void* addr) {
    const struct mach_header* mh = dyld_image_header_containing_address(addr);

    if(!mh) {
        return -1;
    }

    uint32_t count = _dyld_image_count();

    for(uint32_t i = 0; i < count; i++) {
        if(_dyld_get_image_header(i) == mh) {
            return (int)i;
        }
    }

    return -1;
}

// RTLD_NEXT / RTLD_SELF emulation: resolve from the TRUE caller's image
// position (per-image handles in real load order, RTLD_FIRST scoped) instead
// of calling original dlsym with Shadow as the caller — original dlsym would
// resolve RTLD_NEXT relative to the hook's own frame, which is wrong unless
// Shadow happens to sit at the caller's load position.
static void* (*original_dlsym)(void* handle, const char* symbol);

static void* shdw_dlsym_caller_relative(int callerIdx, void* handle, const char* symbol) {
    uint32_t count = _dyld_image_count();
    uint32_t start = (handle == RTLD_NEXT) ? (uint32_t)(callerIdx + 1) : (uint32_t)callerIdx;

    for(uint32_t i = start; i < count; i++) {
        const char* name = _dyld_get_image_name(i);

        if(!name || !name[0]) {
            continue;
        }

        // A lookup handle is deliberately short-lived. Retaining one per
        // image pins unloadable app dylibs and makes the next image event
        // close a large batch through dyld's callbacks.
        void* imgHandle = dlopen(name, RTLD_NOLOAD | RTLD_FIRST);

        if(!imgHandle) {
            continue;
        }

        void* addr = original_dlsym(imgHandle, symbol);

        dlclose(imgHandle);

        if(addr) return addr;
    }

    return NULL;
}

static void* replaced_dlsym(void* handle, const char* symbol) {
    // Each loader operation clears the thread's error state up front.
    _shdw_dyld_error_tls = NULL;

    if(!isCallerExternal()) {
        return original_dlsym(handle, symbol);
    }

    // Hooked system APIs resolve to their replacement regardless of handle —
    // a specific libdyld handle is a dlsym bypass exactly like RTLD_NEXT.
    if(symbol) {
        shdw_sym_policy_entry_t key = { symbol, NULL };
        shdw_sym_policy_entry_t* entry = bsearch(&key, shdw_sym_policy_table, SHADOW_SYM_POLICY_COUNT, sizeof(shdw_sym_policy_entry_t), shdw_sym_policy_compare);

        if(entry) {
            return entry->replacement;
        }

        // The libc/mach/sandbox/mem C-function groups keep their own policy
        // tables (replacements stay static to their files). Consult them so
        // every fishhook-rebound export resolves to its replacement — the
        // GOT-vs-dlsym comparison then agrees for those symbols too.
        void* extra = shdw_sym_policy_lookup_libc(symbol);

        if(!extra) {
            extra = shdw_sym_policy_lookup_mach(symbol);
        }

        if(!extra) {
            extra = shdw_sym_policy_lookup_sandbox(symbol);
        }

        if(!extra) {
            extra = shdw_sym_policy_lookup_mem(symbol);
        }

        if(!extra) {
            extra = shdw_sym_policy_lookup_iokit(symbol);
        }

        if(extra) {
            return extra;
        }
    }

    void* addr = NULL;

    if(handle == RTLD_NEXT || handle == RTLD_SELF) {
        // Caller-relative resolution (see shdw_dlsym_caller_relative).
        int callerIdx = shdw_image_index_of(__builtin_extract_return_addr(__builtin_return_address(0)));

        if(callerIdx < 0) {
            // Caller not in the image list (JIT etc.): degrade to Shadow-
            // relative semantics rather than failing hard.
            addr = original_dlsym(handle, symbol);
        } else {
            addr = shdw_dlsym_caller_relative(callerIdx, handle, symbol);

            if(!addr) {
                shdw_dyld_set_error("symbol not found: %s", symbol);
                return NULL;
            }
        }
    } else {
        addr = original_dlsym(handle, symbol);

        if(!addr) {
            // Real failure: libdyld's own error state is set; keep the TLS
            // error clear so dlerror reports the true cause.
            return NULL;
        }
    }

    // Shadow/JB-only symbols (or a handle that resolved into a protected
    // image): deny with the TLS error, and trip the behavioral escalation.
    if(shdw_addr_is_restricted(addr)) {
        if(symbol) {
            NSLog(@"%@: %@: %s", @"dlsym", @"restricted symbol lookup", symbol);
        }

        // A non-tweak caller resolving a jailbreak symbol is a probe.
        shdw_detector_detected("dlsym");

        // Stock dlsym failure message shape — "symbol not found: <name>",
        // never dlopen's "library not found" (a detector parsing dlerror
        // text would otherwise see the wrong message for the wrong API).
        shdw_dyld_set_error("symbol not found: %s", symbol);
        return NULL;
    }

    return addr;
}

static int (*original_dladdr)(const void* addr, Dl_info* info);
static int replaced_dladdr(const void* addr, Dl_info* info) {
    // Each loader operation clears the thread's error state up front.
    _shdw_dyld_error_tls = NULL;

    // DeviceSecurityKit swizzling check: hide Shadow's UIApplication hook
    // when the caller is the filtered DSK runner. HookKit's %hook stores
    // replacement in ShadowCore (hidden via shdw_own_ranges), but
    // method_getImplementation for hookkit hooks is not in SHDW table, so
    // the generic dladdr hiding (shdw_own_ranges) would return 0 which
    // DSK treats as swizzled. Instead, return the original UIKit dladdr.
    if (addr && shdw_objc_addr_is_hidden(addr)) {
        const char *callerPath = dyld_image_path_containing_address(__builtin_return_address(0));
        if (callerPath && (strstr(callerPath, "DeviceSecurityKitRunner") || strstr(callerPath, "DeviceSecurityKit"))) {
            // For UIApplication.canOpenURL, return the original UIKit IMP's dladdr
            void *orig = shdw_UIApplicationCanOpenURLOriginal();
            if (orig && addr == shdw_UIApplicationCanOpenURLHook()) {
                return original_dladdr(orig, info);
            }
            // For any other hidden addr from DSK, also hide as not swizzled
            // by returning the original's dladdr if we can find it, otherwise
            // return 0 which DSK currently treats as swizzled, so we must
            // return system image instead. Fallback: try to find UIKit's original
            // via dlsym on the selector's class.
            if (orig) {
                return original_dladdr(orig, info);
            }
        }
    }

    // C0-2: Shadow's own code sees truth; every other caller is filtered.
    if(!isCallerExternal()) {
        return original_dladdr(addr, info);
    }

    int result = original_dladdr(addr, info);

    // Restricted address (inside a Shadow-owned or JB image): report "not in
    // any image" — zero the record and return 0, never a fabricated success
    // with a fake executable path (plan Wave 1c; the RTLD_NEXT re-lookup loop
    // is gone — the fallback it fabricated was a fingerprint).
    if(result && (shdw_objc_addr_is_hidden(addr)
        || (info && shdw_is_shadow_runtime_image(info->dli_fname)))) {
        if(info) {
            memset(info, 0, sizeof(Dl_info));
        }

        return 0;
    }

    return result;
}

// --- CFBundle symbol lookup (plan Wave 3): CFBundleGetFunctionPointerForName
// & co. are GOT-style lookups a detector can use to obtain the un-hooked
// original of a fishhook-rebound export — the same bypass the dlsym policy
// table closes, reachable through CoreFoundation instead. Policy: a protected
// bundle path denies outright; a returned address in a protected image is
// NULL; a requested symbol name that matches a hooked system API resolves to
// Shadow's replacement. Installed with the symbol-lookup group.

static BOOL shdw_cfbundle_denied(CFBundleRef bundle) {
    if(!bundle) {
        return NO;
    }

    CFURLRef url = CFBundleCopyBundleURL(bundle);

    if(!url) {
        return NO;
    }

    char buf[PATH_MAX];
    BOOL denied = NO;

    if(CFURLGetFileSystemRepresentation(url, true, (UInt8 *)buf, sizeof(buf))) {
        denied = [_shadow isProtectedImagePath:@(buf)];
    }

    CFRelease(url);
    return denied;
}

static void* shdw_cfbundle_attributed(void* addr, CFStringRef symbolName) {
    if(addr && shdw_addr_is_restricted(addr)) {
        return NULL;
    }

    if(symbolName) {
        char name[256];

        if(CFStringGetCString(symbolName, name, sizeof(name), kCFStringEncodingUTF8)) {
            for(size_t i = 0; i < SHADOW_SYM_POLICY_COUNT; i++) {
                if(strcmp(name, shdw_sym_policy_table[i].name) == 0) {
                    return shdw_sym_policy_table[i].replacement;
                }
            }

            // Same per-file fallback as replaced_dlsym: fishhook-rebound
            // libc/mach/sandbox/mem exports resolve to their replacements.
            void* extra = shdw_sym_policy_lookup_libc(name);

            if(!extra) {
                extra = shdw_sym_policy_lookup_mach(name);
            }

            if(!extra) {
                extra = shdw_sym_policy_lookup_sandbox(name);
            }

            if(!extra) {
                extra = shdw_sym_policy_lookup_mem(name);
            }

            if(!extra) {
                extra = shdw_sym_policy_lookup_iokit(name);
            }

            if(extra) {
                return extra;
            }
        }
    }

    return addr;
}

static void* (*original_CFBundleGetFunctionPointerForName)(CFBundleRef bundle, CFStringRef functionName);
static void* replaced_CFBundleGetFunctionPointerForName(CFBundleRef bundle, CFStringRef functionName) {
    if(!isCallerExternal()) {
        return original_CFBundleGetFunctionPointerForName(bundle, functionName);
    }

    if(shdw_cfbundle_denied(bundle)) {
        return NULL;
    }

    void* addr = original_CFBundleGetFunctionPointerForName(bundle, functionName);
    return shdw_cfbundle_attributed(addr, functionName);
}

static void (*original_CFBundleGetFunctionPointersForNames)(CFBundleRef bundle, CFArrayRef functionNames, void* ftbl[]);
static void replaced_CFBundleGetFunctionPointersForNames(CFBundleRef bundle, CFArrayRef functionNames, void* ftbl[]) {
    if(!isCallerExternal()) {
        return original_CFBundleGetFunctionPointersForNames(bundle, functionNames, ftbl);
    }

    original_CFBundleGetFunctionPointersForNames(bundle, functionNames, ftbl);

    if(!ftbl || !functionNames) {
        return;
    }

    BOOL denied = shdw_cfbundle_denied(bundle);
    CFIndex count = CFArrayGetCount(functionNames);

    for(CFIndex i = 0; i < count; i++) {
        if(denied) {
            ftbl[i] = NULL;
            continue;
        }

        CFStringRef name = (CFStringRef)CFArrayGetValueAtIndex(functionNames, i);
        ftbl[i] = shdw_cfbundle_attributed(ftbl[i], name);
    }
}

static void* (*original_CFBundleGetDataPointerForName)(CFBundleRef bundle, CFStringRef symbolName);
static void* replaced_CFBundleGetDataPointerForName(CFBundleRef bundle, CFStringRef symbolName) {
    if(!isCallerExternal()) {
        return original_CFBundleGetDataPointerForName(bundle, symbolName);
    }

    if(shdw_cfbundle_denied(bundle)) {
        return NULL;
    }

    void* addr = original_CFBundleGetDataPointerForName(bundle, symbolName);
    return shdw_cfbundle_attributed(addr, symbolName);
}

// A hidden image is one absent from the filtered collection: updatelibs only
// ever adds safe (non-restricted) images, so anything not in the collection
// is hidden. mh == NULL (unknown) is never "hidden".
static BOOL shdw_dyld_image_is_hidden(const struct mach_header* mh) {
    if(!mh) {
        return NO;
    }

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];

    for(NSDictionary* dylib in _dyld_collection) {
        if((struct mach_header *)[dylib[@"mach_header"] pointerValue] == mh) {
            return NO;
        }
    }

    return YES;
}

// iOS 12+ SPI: resolves addresses to their containing image (uuid + offset).
// dyld zero-fills entries for addresses it doesn't know; extend the same
// "unknown" signal to PROTECTED addresses (inside Shadow-owned or JB images)
// so stack-backtrace symbolication can't walk past the dyld API filter.
static void (*original_dyld_images_for_addresses)(unsigned count, const void* addresses[], struct dyld_image_uuid_offset infos[]);
static void replaced_dyld_images_for_addresses(unsigned count, const void* addresses[], struct dyld_image_uuid_offset infos[]) {
    if(!isCallerExternal()) {
        return original_dyld_images_for_addresses(count, addresses, infos);
    }

    original_dyld_images_for_addresses(count, addresses, infos);

    if(!infos || !addresses) {
        return;
    }

    for(unsigned i = 0; i < count; i++) {
        if(shdw_addr_is_restricted(addresses[i])) {
            memset(&infos[i], 0, sizeof(infos[i]));
        }
    }
}

// iOS 12+ SPI: register a per-load callback (replays currently-loaded images
// at registration). Same fan-out pattern as the add_image registration above:
// external (app/detector) callbacks are stored in slots, and our own handler —
// registered with real dyld at hook-install time — delivers only visible
// images, so a hidden image never reaches a detector's callback, even on
// later loads. Shadow's own registrations pass through to real dyld (truth).
//
// TODO (device-test territory, NOT attempted): the fan-out below runs the
// app's callbacks from Shadow's own handler frame — a detector can spot the
// extra frame and, worse, Shadow is on the callback's stack while dyld holds
// its load lock. The correct shape is authenticated tail-branch thunks that
// jump into each app callback without an intervening Shadow frame. The same
// applies to the bulk variant below and to the objc-notifier fan-out below.

// --- ObjC-mapped notifiers (plan Wave 1c): _dyld_objc_notify_register
// (vendored dyld_priv.h) and objc_addLoadImageFunc (iOS 15+, resolved by
// name) deliver a callback for EVERY loaded image, including ones hidden
// from the enumeration APIs. External registrants are stored in the slot
// arrays below and driven from Shadow's own dyld-registered handlers, which
// filter first — the same storage/fan-out shape as the register-for-image-
// loads surface above. Shadow's own registrations pass through to the
// originals (truth).
//
// NOTE: we deliberately do NOT register a handler with real
// _dyld_objc_notify_register — dyld keeps a SINGLE objc-notifier slot and a
// second registration would overwrite libobjc's, breaking the ObjC runtime.
// The per-image fan-out is driven from the image-load handler (iOS 12+) and
// the remove-image handler (unmapped) instead; on older OSes stored
// callbacks still get the registration-time replay and later loads stay
// invisible to them (fail soft). The ObjC runtime itself registered pre-hook
// and keeps dyld's unfiltered notifier — only post-hook (detector)
// registrants are captured, same limitation as the tail-branch thunk TODO
// above.
static _dyld_objc_notify_mapped shdw_objc_mapped_cbs[SHADOW_MAX_OBJC_NOTIFY_CBS];
static _dyld_objc_notify_init shdw_objc_init_cbs[SHADOW_MAX_OBJC_NOTIFY_CBS];
static _dyld_objc_notify_unmapped shdw_objc_unmapped_cbs[SHADOW_MAX_OBJC_NOTIFY_CBS];

// objc_addLoadImageFunc (iOS 15+): function-pointer-only registration (no
// context) — one flat callback list, mirroring the load-image slots above.
typedef void (*shdw_objc_func_load_image)(const struct mach_header* mh);
static shdw_objc_func_load_image shdw_objc_loadimage_cbs[SHADOW_MAX_OBJC_NOTIFY_CBS];

// Per-image fan-out for the objc notifier: mapped delivered as count=1 (the
// callback contract is array-based; a one-element batch is valid), plus the
// init and addLoadImageFunc callbacks. Driven from shdw_image_load_handler,
// which already excluded hidden images.
static void shdw_objc_notify_image(const struct mach_header* mh, const char* path) {
    for(int i = 0; i < SHADOW_MAX_OBJC_NOTIFY_CBS; i++) {
        if(shdw_objc_mapped_cbs[i]) {
            const struct mach_header* mhs[] = { mh };
            const char* paths[] = { path };
            shdw_objc_mapped_cbs[i](1, paths, mhs);
        }

        if(shdw_objc_init_cbs[i]) {
            // ponytail: fires at load-notifier time, not at initializer-run
            // time (dyld's real init notifier fires later); close enough for
            // visibility purposes, device-test territory if ordering matters.
            shdw_objc_init_cbs[i](path, mh);
        }

        if(shdw_objc_loadimage_cbs[i]) {
            shdw_objc_loadimage_cbs[i](mh);
        }
    }
}

// Unmapped fan-out, driven from shadowhook_dyld_updatelibs_r — only ever
// called for images being removed from the collection (visible ones), so
// hidden images never reach the unmapped callbacks.
static void shdw_objc_notify_unmapped(const char* path, const struct mach_header* mh) {
    for(int i = 0; i < SHADOW_MAX_OBJC_NOTIFY_CBS; i++) {
        if(shdw_objc_unmapped_cbs[i]) {
            shdw_objc_unmapped_cbs[i](path, mh);
        }
    }
}

static void (*original_dyld_objc_notify_register)(_dyld_objc_notify_mapped mapped, _dyld_objc_notify_init init, _dyld_objc_notify_unmapped unmapped);
static void replaced_dyld_objc_notify_register(_dyld_objc_notify_mapped mapped, _dyld_objc_notify_init init, _dyld_objc_notify_unmapped unmapped) {
    // C0-2: Shadow's own registrations pass through to real dyld (truth);
    // every other caller registers with the filtered replay. (Not forwarding
    // external registrations also protects dyld's single objc-notifier slot —
    // an external all-NULL registration would otherwise clobber libobjc's.)
    if(!isCallerExternal()) {
        return original_dyld_objc_notify_register(mapped, init, unmapped);
    }

    if(mapped) {
        for(int i = 0; i < SHADOW_MAX_OBJC_NOTIFY_CBS; i++) {
            if(!shdw_objc_mapped_cbs[i]) {
                shdw_objc_mapped_cbs[i] = mapped;
                break;
            }
        }
    }

    if(init) {
        for(int i = 0; i < SHADOW_MAX_OBJC_NOTIFY_CBS; i++) {
            if(!shdw_objc_init_cbs[i]) {
                shdw_objc_init_cbs[i] = init;
                break;
            }
        }
    }

    if(unmapped) {
        for(int i = 0; i < SHADOW_MAX_OBJC_NOTIFY_CBS; i++) {
            if(!shdw_objc_unmapped_cbs[i]) {
                shdw_objc_unmapped_cbs[i] = unmapped;
                break;
            }
        }
    }

    // Replay the visible images to `mapped` now, mirroring dyld's
    // registration-time replay (dyld replays only the mapped callback). dyld
    // would further filter to objc images; passing every visible image is
    // harmless — the callbacks tolerate non-objc entries.
    if(mapped) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        NSUInteger count = MIN([_dyld_collection count], (NSUInteger) SHADOW_DYLD_MIRROR_CAPACITY);
        const char* paths[SHADOW_DYLD_MIRROR_CAPACITY];
        const struct mach_header* mhs[SHADOW_DYLD_MIRROR_CAPACITY];

        for(NSUInteger i = 0; i < count; i++) {
            NSDictionary* dylib = _dyld_collection[i];
            mhs[i] = (struct mach_header *)[dylib[@"mach_header"] pointerValue];
            paths[i] = [dylib[@"name"] fileSystemRepresentation];
        }

        mapped((unsigned) count, paths, mhs);
    }
}

static void (*original_objc_addLoadImageFunc)(shdw_objc_func_load_image func);
static void replaced_objc_addLoadImageFunc(shdw_objc_func_load_image func) {
    if(!isCallerExternal() || !func) {
        return original_objc_addLoadImageFunc(func);
    }

    for(int i = 0; i < SHADOW_MAX_OBJC_NOTIFY_CBS; i++) {
        if(!shdw_objc_loadimage_cbs[i]) {
            shdw_objc_loadimage_cbs[i] = func;
            break;
        }
    }

    // Replay the visible images now (libobjc itself does not replay, but the
    // other registration surfaces here do — a registrant sees the same
    // visible set through every API).
    NSArray* _dyld_collection = [_shdw_dyld_collection copy];

    for(NSDictionary* dylib in _dyld_collection) {
        func((struct mach_header *)[dylib[@"mach_header"] pointerValue]);
    }
}

#define SHADOW_MAX_IMAGE_LOAD_CBS 8
static void (*shdw_image_load_cbs[SHADOW_MAX_IMAGE_LOAD_CBS])(const struct mach_header* mh, const char* path, bool unloadable);
static void shdw_image_load_handler(const struct mach_header* mh, const char* path, bool unloadable) {
    if(shdw_dyld_image_is_hidden(mh)) {
        return;
    }

    for(int i = 0; i < SHADOW_MAX_IMAGE_LOAD_CBS; i++) {
        if(shdw_image_load_cbs[i]) {
            shdw_image_load_cbs[i](mh, path, unloadable);
        }
    }

    // ObjC-mapped notifier fan-out (visible images only — the hidden check
    // above already excluded protected images).
    shdw_objc_notify_image(mh, path);
}
static void (*original_dyld_register_for_image_loads)(void (*func)(const struct mach_header* mh, const char* path, bool unloadable));
static void replaced_dyld_register_for_image_loads(void (*func)(const struct mach_header* mh, const char* path, bool unloadable)) {
    // C0-2: Shadow's own registrations (and NULL funcs) pass through to real
    // dyld (truth); every other caller registers with the filtered fan-out.
    if(!isCallerExternal() || !func) {
        return original_dyld_register_for_image_loads(func);
    }

    for(int i = 0; i < SHADOW_MAX_IMAGE_LOAD_CBS; i++) {
        if(!shdw_image_load_cbs[i]) {
            shdw_image_load_cbs[i] = func;
            break;
        }
    }

    // Replay the visible images now, mirroring dyld's registration-time replay.
    NSArray* _dyld_collection = [_shdw_dyld_collection copy];

    for(NSDictionary* dylib in _dyld_collection) {
        func((struct mach_header *)[dylib[@"mach_header"] pointerValue], [dylib[@"name"] fileSystemRepresentation], false);
    }
}

// iOS 13+ SPI: bulk variant — one callback with the whole image list at
// registration, then per-dlopen batches. Filtered the same way.
#define SHADOW_MAX_BULK_LOAD_CBS 8
static void (*shdw_bulk_load_cbs[SHADOW_MAX_BULK_LOAD_CBS])(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]);
static void shdw_bulk_load_handler(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]) {
    const struct mach_header* visible_mhs[SHADOW_DYLD_MIRROR_CAPACITY];
    const char* visible_paths[SHADOW_DYLD_MIRROR_CAPACITY];
    unsigned n = 0;
    unsigned cap = MIN(imageCount, (unsigned) SHADOW_DYLD_MIRROR_CAPACITY);

    for(unsigned i = 0; i < cap; i++) {
        if(shdw_dyld_image_is_hidden(mhs[i])) {
            continue;
        }

        visible_mhs[n] = mhs[i];
        visible_paths[n] = paths ? paths[i] : NULL;
        n++;
    }

    for(int i = 0; i < SHADOW_MAX_BULK_LOAD_CBS; i++) {
        if(shdw_bulk_load_cbs[i]) {
            shdw_bulk_load_cbs[i](n, visible_mhs, visible_paths);
        }
    }
}
static void (*original_dyld_register_for_bulk_image_loads)(void (*func)(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]));
static void replaced_dyld_register_for_bulk_image_loads(void (*func)(unsigned imageCount, const struct mach_header* mhs[], const char* paths[])) {
    // C0-2: same polarity as the per-image variant above — internal passes
    // through (truth), external registers with the filtered fan-out.
    if(!isCallerExternal() || !func) {
        return original_dyld_register_for_bulk_image_loads(func);
    }

    for(int i = 0; i < SHADOW_MAX_BULK_LOAD_CBS; i++) {
        if(!shdw_bulk_load_cbs[i]) {
            shdw_bulk_load_cbs[i] = func;
            break;
        }
    }

    // Replay the visible images now.
    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    NSUInteger count = MIN([_dyld_collection count], (NSUInteger) SHADOW_DYLD_MIRROR_CAPACITY);
    const struct mach_header* mhs[SHADOW_DYLD_MIRROR_CAPACITY];
    const char* paths[SHADOW_DYLD_MIRROR_CAPACITY];

    for(NSUInteger i = 0; i < count; i++) {
        NSDictionary* dylib = _dyld_collection[i];
        mhs[i] = (struct mach_header *)[dylib[@"mach_header"] pointerValue];
        paths[i] = [dylib[@"name"] fileSystemRepresentation];
    }

    func((unsigned) count, mhs, paths);
}

// --- Process-snapshot SPI (plan Wave 1c; Phase 3 deferred item): the
// _dyld_process_info_* family hands out an opaque snapshot of the task's
// image list. The struct layout is NOT in the vendored dyld_priv.h
// (macOS-only dyld_process_info.h; absent from the iOS SDKs here), so a
// filtered rebuild of the returned handle is impossible without hard-coded
// offsets (rejected: arm64e-unsafe). Documented SKIP path (per plan):
// external callers get dyld's "no process info" state (NULL create + zero
// count), a failure path every caller must handle anyway, and every family
// accessor is hooked with a NULL-handle guard so no external caller can
// crash dyld dereferencing the NULL handle our create handed out. Truth for
// Shadow's own code. External callers that somehow hold a REAL handle
// (captured before the hook installed) still get their get_images output
// filtered below. The dyld4-era accessor names (_dyld_process_info_release,
// _dyld_process_info_get_state, _dyld_process_info_get_image_path/uuid) are
// resolved by name at install alongside the legacy _dyld_process_info_destroy.
typedef struct _dyld_process_info* shdw_dyld_process_info_t;

struct shdw_dyld_process_info_image {
    uuid_t imageUUID;
    const char* imagePath;
    const struct mach_header* imageLoadAddress;
    bool inSharedCache;
};

// Path predicate for the NS* lookup family (defined with it below); used by
// the process-info output filter above it.
static BOOL shdw_dyld_path_restricted(const char* path);

static shdw_dyld_process_info_t (*original_dyld_process_info_create)(task_t task, uint64_t timestamp, uint32_t* returnCount);
static shdw_dyld_process_info_t replaced_dyld_process_info_create(task_t task, uint64_t timestamp, uint32_t* returnCount) {
    if(!isCallerExternal()) {
        return original_dyld_process_info_create(task, timestamp, returnCount);
    }

    if(returnCount) {
        *returnCount = 0;
    }

    return NULL;
}

static void (*original_dyld_process_info_get_images)(shdw_dyld_process_info_t info, struct shdw_dyld_process_info_image* images, uint32_t* infoCount);
static void replaced_dyld_process_info_get_images(shdw_dyld_process_info_t info, struct shdw_dyld_process_info_image* images, uint32_t* infoCount) {
    if(!isCallerExternal()) {
        return original_dyld_process_info_get_images(info, images, infoCount);
    }

    // External callers can only ever hold NULL handles (create is filtered
    // above); the original would crash dereferencing NULL.
    if(!info) {
        return;
    }

    original_dyld_process_info_get_images(info, images, infoCount);

    // A REAL handle here means the caller captured it before the hook
    // installed: filter the output the same way the collection mirror does —
    // drop restricted/Shadow-owned entries and compact. The caller sized its
    // buffer from the (pre-hook) count, so shrinking infoCount is always
    // safe; entries are only ever removed, never added.
    if(!images || !infoCount) {
        return;
    }

    uint32_t kept = 0;
    uint32_t total = *infoCount;

    for(uint32_t i = 0; i < total; i++) {
        if(shdw_dyld_path_restricted(images[i].imagePath) || shdw_addr_is_restricted(images[i].imageLoadAddress)) {
            continue;
        }

        if(kept != i) {
            images[kept] = images[i];
        }

        kept++;
    }

    *infoCount = kept;
}

static void (*original_dyld_process_info_destroy)(shdw_dyld_process_info_t info);
static void replaced_dyld_process_info_destroy(shdw_dyld_process_info_t info) {
    if(!isCallerExternal()) {
        return original_dyld_process_info_destroy(info);
    }

    if(!info) {
        return;
    }

    original_dyld_process_info_destroy(info);
}

// dyld4-era (iOS 15+) accessors, resolved by name at install. NULL-handle
// guards: external callers only ever hold the NULL our create returned; the
// originals would crash dereferencing it.
static shdw_dyld_process_state_t (*original_dyld_process_info_get_state)(shdw_dyld_process_info_t info);
static shdw_dyld_process_state_t replaced_dyld_process_info_get_state(shdw_dyld_process_info_t info) {
    if(!isCallerExternal()) {
        return original_dyld_process_info_get_state(info);
    }

    if(!info) {
        // dyld's own answer for a live process — a detector reading its own
        // process state sees the same value from the real API.
        return shdw_dyld_process_state_running;
    }

    return original_dyld_process_info_get_state(info);
}

static void (*original_dyld_process_info_release)(shdw_dyld_process_info_t info);
static void replaced_dyld_process_info_release(shdw_dyld_process_info_t info) {
    if(!isCallerExternal()) {
        return original_dyld_process_info_release(info);
    }

    if(!info) {
        return;
    }

    original_dyld_process_info_release(info);
}

static void (*original_dyld_process_info_get_image_path)(shdw_dyld_process_info_t info, struct shdw_dyld_process_info_image* image, char* buffer, uint32_t bufferSize);
static void replaced_dyld_process_info_get_image_path(shdw_dyld_process_info_t info, struct shdw_dyld_process_info_image* image, char* buffer, uint32_t bufferSize) {
    if(!isCallerExternal()) {
        return original_dyld_process_info_get_image_path(info, image, buffer, bufferSize);
    }

    if(!info) {
        if(buffer && bufferSize) {
            buffer[0] = '\0';
        }

        return;
    }

    original_dyld_process_info_get_image_path(info, image, buffer, bufferSize);
}

static void (*original_dyld_process_info_get_image_uuid)(shdw_dyld_process_info_t info, struct shdw_dyld_process_info_image* image, uuid_t uuid);
static void replaced_dyld_process_info_get_image_uuid(shdw_dyld_process_info_t info, struct shdw_dyld_process_info_image* image, uuid_t uuid) {
    if(!isCallerExternal()) {
        return original_dyld_process_info_get_image_uuid(info, image, uuid);
    }

    if(!info) {
        if(uuid) {
            memset(uuid, 0, sizeof(uuid_t));
        }

        return;
    }

    original_dyld_process_info_get_image_uuid(info, image, uuid);
}

// --- Legacy NS* image/symbol lookup APIs (plan Wave 1c): declared in the
// SDK's mach-o/dyld.h but __API_UNAVAILABLE(ios) — resolved by name at
// install and skipped silently on OSes that never exported them (same
// discipline as the SJLJ-guarded _dyld_find_unwind_sections above).
// NSSymbol is a typedef of void*; the originals are typed accordingly.

// Same path policy as the collection gate in updatelibs / the dlopen
// resolver: restricted by the ruleset OR a protected image name.
static BOOL shdw_dyld_path_restricted(const char* path) {
    if(!path || !path[0]) {
        return NO;
    }

    NSString* p = [NSString stringWithUTF8String:path];
    if(shdw_path_is_in_main_bundle(p)) return NO;
    return [_shadow isPathRestricted:p options:@{kShadowRestrictionEnableResolve : @(NO)}] || [_shadow isProtectedImagePath:p];
}

static const struct mach_header* (*original_NSAddImage)(const char* image_name, uint32_t options);
static const struct mach_header* replaced_NSAddImage(const char* image_name, uint32_t options) {
    if(!isCallerExternal()) {
        return original_NSAddImage(image_name, options);
    }

    if(shdw_dyld_path_restricted(image_name)) {
        return NULL;
    }

    return original_NSAddImage(image_name, options);
}

static void* (*original_NSLookupSymbolInImage)(const struct mach_header* image, const char* symbolName, uint32_t options);
static void* replaced_NSLookupSymbolInImage(const struct mach_header* image, const char* symbolName, uint32_t options) {
    if(!isCallerExternal()) {
        return original_NSLookupSymbolInImage(image, symbolName, options);
    }

    if(!image || shdw_addr_is_restricted(image)) {
        return NULL;
    }

    void* result = original_NSLookupSymbolInImage(image, symbolName, options);

    // The symbol's own address may sit in a restricted image even when the
    // lookup target is not (options-dependent resolution) — same
    // result-address deny as replaced_dlsym.
    if(result && shdw_addr_is_restricted(result)) {
        return NULL;
    }

    return result;
}

static int32_t (*original_NSVersionOfRunTimeLibrary)(const char* libraryName);
static int32_t replaced_NSVersionOfRunTimeLibrary(const char* libraryName) {
    if(!isCallerExternal()) {
        return original_NSVersionOfRunTimeLibrary(libraryName);
    }

    // -1 is dyld's own "not found" signal for this API.
    if(shdw_dyld_path_restricted(libraryName)) {
        return -1;
    }

    return original_NSVersionOfRunTimeLibrary(libraryName);
}

// Real dyld function pointers for the modern load/bulk-registration SPIs,
// resolved by name from libdyld in shadowhook_dyld. The internal handlers
// (shdw_image_load_handler / shdw_bulk_load_handler) MUST be registered with
// real dyld through these raw pointers, not through the hooked variants
// out-params (original_dyld_register_*): those are only filled when the hook
// batch executes (dylib.x queues first), so calling them at install time
// would call NULL and crash.
static void (*shdw_real_register_for_image_loads)(void (*func)(const struct mach_header* mh, const char* path, bool unloadable));
static void (*shdw_real_register_for_bulk_image_loads)(void (*func)(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]));

// Undo the memory-hiding patch: write dyld's original field values back into
// dyld_all_image_infos, using the same vm_protect fail-soft dance as the
// patch (originals captured at first patch time above). Only called under
// `_shdw_dyld_mirror_lock`; sets `_shdw_mirror_currently_patched = NO` only
// on success — on vm_protect failure the mirror stays applied and
// `_shdw_mirror_protect_failed` latches, disabling the patch path as well.
// Reachable via the AR2 emergency kill-switch (MemoryLevelHiding pref off):
// the patch is unconditional by default, but a misbehaving patch on a new iOS
// must be disableable without a reinstall — flipping the pref restores dyld's
// true struct. The VM_MAKE_TAG/VM_PROTECT dance is retained verbatim.
static void shdw_dyld_publish_task_info_mirror(void) {
    if(!_shdw_all_image_infos || _shdw_task_dyld_info_mirror_alloc_failed) {
        return;
    }

    if(!_shdw_task_dyld_info_mirror) {
        vm_address_t address = 0;
        if(vm_allocate(mach_task_self(), &address, sizeof(*_shdw_task_dyld_info_mirror), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
            _shdw_task_dyld_info_mirror_alloc_failed = YES;
            NSLog(@"shadow: dyld: failed to allocate TASK_DYLD_INFO mirror, falling back to live struct");
            return;
        }
        _shdw_task_dyld_info_mirror = (struct dyld_all_image_infos*)address;
    }

    memcpy(_shdw_task_dyld_info_mirror, _shdw_all_image_infos,
        sizeof(*_shdw_task_dyld_info_mirror));
}

static void shdw_dyld_mirror_restore_originals(void) {
    if(!_shdw_originals_captured) {
        return;
    }

    mach_vm_address_t page = (mach_vm_address_t) _shdw_all_image_infos & ~(mach_vm_address_t) (vm_page_size - 1);

    if(!_shdw_mirror_protect_failed) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        vm_address_t region = page;
        vm_size_t region_size = 0;
        mach_port_t object_name = MACH_PORT_NULL;

        if(vm_region_64(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &info_count, &object_name) == KERN_SUCCESS) {
            _shdw_mirror_original_protection = info.protection;
        }
    }

    if(!_shdw_mirror_protect_failed && vm_protect(mach_task_self(), page, vm_page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
        _shdw_all_image_infos->infoArray = _shdw_original_info_array;
        _shdw_all_image_infos->infoArrayCount = _shdw_original_info_array_count;
        _shdw_all_image_infos->uuidArray = _shdw_real_uuid_array;
        _shdw_all_image_infos->uuidArrayCount = _shdw_real_uuid_count;

        // Atlas (v16+, iOS 11+): the patch zeroed both, put dyld's originals back.
        if(_shdw_all_image_infos->version >= 16) {
            _shdw_all_image_infos->compact_dyld_image_info_addr = _shdw_original_atlas_addr;
            _shdw_all_image_infos->compact_dyld_image_info_size = _shdw_original_atlas_size;
        }

        vm_protect(mach_task_self(), page, vm_page_size, FALSE, _shdw_mirror_original_protection);
        shdw_dyld_publish_task_info_mirror();
        _shdw_mirror_currently_patched = NO;
    } else if(!_shdw_mirror_protect_failed) {
        _shdw_mirror_protect_failed = YES;
        NSLog(@"shadow: dyld: vm_protect failed restoring dyld_all_image_infos, memory hiding stays applied (fail soft)");
    }
}

static BOOL shdw_dyld_image_uuid(const struct mach_header* mh, uuid_t uuid) {
    const struct mach_header_64* header = (const struct mach_header_64*)mh;

    if(!header || header->magic != MH_MAGIC_64 || (header->flags & MH_DYLIB_IN_CACHE)) {
        return NO;
    }

    const struct load_command* command = (const struct load_command*)(header + 1);

    for(uint32_t i = 0; i < header->ncmds; i++) {
        if(command->cmdsize < sizeof(*command)) {
            return NO;
        }

        if(command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            memcpy(uuid, ((const struct uuid_command*)command)->uuid, sizeof(uuid_t));
            return YES;
        }

        command = (const struct load_command*)((const char*)command + command->cmdsize);
    }

    return NO;
}

static void shadowhook_dyld_rebuild_dyldinfo(void) {
    // No prefs I/O here (plan Wave 1c): the mirror patch is unconditional, so
    // nothing runs before the lock except the collection copy itself.
    // TODO (device-test territory, NOT attempted): notifier-inline rebuild —
    // this rebuild runs from the add/remove-image callbacks; inlining the
    // mirror publication into dyld's own notifier path (no collection copy,
    // no lock hop) is the target shape once the add/remove surface is
    // replaced by tail-branch thunks.
    pthread_mutex_lock(&_shdw_dyld_mirror_lock);

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    NSUInteger rawCount = [_dyld_collection count];
    NSUInteger count = MIN(rawCount, (NSUInteger) SHADOW_DYLD_MIRROR_CAPACITY);
    if(rawCount > 4000) {
        static BOOL warnedCap = NO;
        if(!warnedCap) { warnedCap = YES; NSLog(@"shadow: dyld: image count %lu %s mirror capacity %d%s", (unsigned long)rawCount, rawCount > SHADOW_DYLD_MIRROR_CAPACITY ? "exceeds" : "near", SHADOW_DYLD_MIRROR_CAPACITY, rawCount > SHADOW_DYLD_MIRROR_CAPACITY ? ", truncating (grow-on-demand TODO)" : ""); }
    }

    // C4: refresh the hot-path snapshot (always). Fill the inactive buffer,
    // then publish it. On allocation failure nothing is published — the
    // previously published snapshot (or none) stays in place, and the
    // accessors fall back to the collection until the first successful
    // publish. Readers take this lock (see the accessors), so the publish
    // needs no atomics; kept as one anyway for clarity.
    static BOOL snapshotAllocFailed = NO;

    if(!snapshotAllocFailed) {
        for(int bufferIndex = 0; bufferIndex < 2; bufferIndex++) {
            if(!_shdw_dyld_snapshot_buffers[bufferIndex]
            && vm_allocate(mach_task_self(), (vm_address_t *) &_shdw_dyld_snapshot_buffers[bufferIndex], sizeof(shdw_dyld_snapshot_t), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                snapshotAllocFailed = YES;
                NSLog(@"shadow: dyld: failed to allocate image snapshot, enumeration hooks report an empty image list (fail soft)");
                break;
            }
        }
    }

    if(!snapshotAllocFailed) {
        shdw_dyld_snapshot_t* snapshot = (_shdw_dyld_snapshot == _shdw_dyld_snapshot_buffers[1]) ? _shdw_dyld_snapshot_buffers[0] : _shdw_dyld_snapshot_buffers[1];

        snapshot->count = (uint32_t) count;

        for(NSUInteger i = 0; i < count; i++) {
            NSDictionary* dylib = _dyld_collection[i];

            snapshot->entry[i].mh = (struct mach_header *)[dylib[@"mach_header"] pointerValue];
            snapshot->entry[i].slide = (intptr_t)[dylib[@"slide"] pointerValue];
            snapshot->entry[i].name = [dylib[@"name"] UTF8String];
        }

        __atomic_store_n(&_shdw_dyld_snapshot, snapshot, __ATOMIC_RELEASE);
    }

    // No struct to patch (pre-modern iOS): the API-level enumeration hooks
    // above still hide images (fail soft).
    if(!_shdw_all_image_infos) {
        pthread_mutex_unlock(&_shdw_dyld_mirror_lock);
        return;
    }

    // AR2 emergency kill-switch (MemoryLevelHiding pref off): restore dyld's
    // original struct (if we patched it) and never re-patch. The API-level
    // enumeration hooks above still hide images; only the direct-memory-read
    // surface (task_info / _dyld_get_all_image_infos) is re-exposed. This is
    // the crash escape hatch — a misbehaving patch on a new iOS must be
    // disableable without a reinstall.
    if(!shdw_memory_hiding_enabled) {
        if(_shdw_mirror_currently_patched) {
            shdw_dyld_mirror_restore_originals();
        }

        pthread_mutex_unlock(&_shdw_dyld_mirror_lock);
        return;
    }

    // The patch is unconditional (no pref gate): untrusted callers reading
    // dyld_all_image_infos directly — task_info TASK_DYLD_INFO /
    // _dyld_get_all_image_infos — always see the filtered mirror. The
    // replaced_task_info hook complements the mirror: it detects external
    // TASK_DYLD_INFO probes on mach_task_self() (isCallerExternal) and
    // escalates via shdw_detector_detected while still returning the filtered
    // mirror; non-self tasks are passed through untouched (device-test
    // territory for remote task handling).

    // Allocate the fixed-capacity generation buffers once (lazily).
    // vm_allocate'd, never freed or reallocated: the published pointers can't
    // dangle, and a reader holding the previous generation never sees it
    // rewritten while the new one is being published. Two-generation
    // publication: a reader holding a pointer across more than one rebuild
    // may observe that generation rewritten in place — bounded by the fixed
    // capacity, never an over-read.
    static BOOL mirrorAllocFailed = NO;

    if(!mirrorAllocFailed) {
        for(int bufferIndex = 0; bufferIndex < 2; bufferIndex++) {
            if(!_shdw_dyld_info_buffers[bufferIndex]
            && vm_allocate(mach_task_self(), (vm_address_t *) &_shdw_dyld_info_buffers[bufferIndex], SHADOW_DYLD_MIRROR_CAPACITY * sizeof(struct dyld_image_info), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                mirrorAllocFailed = YES;
                NSLog(@"shadow: dyld: failed to allocate info mirror, memory hiding disabled (fail soft)");
                break;
            }
        }

        for(int bufferIndex = 0; bufferIndex < 2; bufferIndex++) {
            if(!_shdw_dyld_uuid_buffers[bufferIndex]
            && vm_allocate(mach_task_self(), (vm_address_t *) &_shdw_dyld_uuid_buffers[bufferIndex], SHADOW_DYLD_MIRROR_CAPACITY * sizeof(struct dyld_uuid_info), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                mirrorAllocFailed = YES;
                NSLog(@"shadow: dyld: failed to allocate uuid mirror, memory hiding disabled (fail soft)");
                break;
            }
        }
    }

    // Capture static restore fields before the first publication. UUID arrays
    // differ: dyld republishes them as images load, so refresh the source when
    // it is a real (not our mirror) non-empty array.
    if(!_shdw_originals_captured) {
        _shdw_originals_captured = YES;
        _shdw_real_uuid_array = _shdw_all_image_infos->uuidArray;
        _shdw_real_uuid_count = _shdw_all_image_infos->uuidArrayCount;
        _shdw_original_info_array = _shdw_all_image_infos->infoArray;
        _shdw_original_info_array_count = _shdw_all_image_infos->infoArrayCount;

        // Atlas (v16+, iOS 11+): the patch zeroes both fields, so keep the
        // originals for the restore.
        if(_shdw_all_image_infos->version >= 16) {
            _shdw_original_atlas_addr = _shdw_all_image_infos->compact_dyld_image_info_addr;
            _shdw_original_atlas_size = _shdw_all_image_infos->compact_dyld_image_info_size;
        }
    } else if(_shdw_all_image_infos->uuidArray != _shdw_dyld_uuid_published
           && _shdw_all_image_infos->uuidArray
           && _shdw_all_image_infos->uuidArrayCount) {
        _shdw_real_uuid_array = _shdw_all_image_infos->uuidArray;
        _shdw_real_uuid_count = _shdw_all_image_infos->uuidArrayCount;
    }

    if(!mirrorAllocFailed) {
        // Pick the inactive generation buffers (the ones not currently
        // published); a reader holding the other generation keeps seeing its
        // intact contents until the next swap.
        struct dyld_image_info* infoGen = (_shdw_dyld_info_published == _shdw_dyld_info_buffers[1]) ? _shdw_dyld_info_buffers[0] : _shdw_dyld_info_buffers[1];
        struct dyld_uuid_info* uuidGen = (_shdw_dyld_uuid_published == _shdw_dyld_uuid_buffers[1]) ? _shdw_dyld_uuid_buffers[0] : _shdw_dyld_uuid_buffers[1];

        // Filtered dyld_image_info array, one entry per collection entry.
        for(NSUInteger i = 0; i < count; i++) {
            NSDictionary* dylib = _dyld_collection[i];

            infoGen[i].imageLoadAddress = (struct mach_header *)[dylib[@"mach_header"] pointerValue];
            infoGen[i].imageFilePath = [dylib[@"name"] UTF8String];

            // Real mtime from the file: a synthetic 0 is a fingerprint for a
            // raw reader cross-checking imageFilePath against stat(). The
            // stat call originates from Shadow-owned code, so the hooked
            // stat classifies it internal and passes through.
            struct stat st;

            if(stat([dylib[@"name"] fileSystemRepresentation], &st) == 0) {
                infoGen[i].imageFileModDate = st.st_mtimespec.tv_sec;
            } else {
                infoGen[i].imageFileModDate = 0;
            }
        }

        // Build the filtered UUID table from the visible, non-shared-cache
        // images. dyld mutates its live UUID table while this mirror owns the
        // public pointer, so rescanning that table can omit a fresh dlopen.
        NSUInteger uuidCount = 0;

        for(NSUInteger i = 0; i < count; i++) {
            const struct mach_header* mh = (struct mach_header *)[_dyld_collection[i][@"mach_header"] pointerValue];
            uuid_t uuid;

            if(shdw_dyld_image_uuid(mh, uuid)) {
                uuidGen[uuidCount].imageLoadAddress = mh;
                memcpy(uuidGen[uuidCount].imageUUID, uuid, sizeof(uuid_t));
                uuidCount++;
            }
        }

        // Publish into dyld's live struct (plain, non-PAC-signed pointers). The
        // page may be read-only: make it writable via vm_protect, write only
        // the four array fields, then restore the original protection. On
        // failure we log once and keep the previous state (fail soft). The
        // bookkeeping statics are shared with the restore path
        // (shdw_dyld_mirror_restore_originals) — a latched failure disables both.
        mach_vm_address_t page = (mach_vm_address_t) _shdw_all_image_infos & ~(mach_vm_address_t) (vm_page_size - 1);

        if(!_shdw_mirror_protect_failed) {
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
            vm_address_t region = page;
            vm_size_t region_size = 0;
            mach_port_t object_name = MACH_PORT_NULL;

            if(vm_region_64(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &info_count, &object_name) == KERN_SUCCESS) {
                _shdw_mirror_original_protection = info.protection;
            }
        }

        if(!_shdw_mirror_protect_failed && vm_protect(mach_task_self(), page, vm_page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
            // Count first, pointer last: a reader catching the swap sees the
            // new count with the previous generation's entries — stale but
            // within the fixed capacity — never a torn or over-read buffer.
            _shdw_all_image_infos->infoArrayCount = (uint32_t) count;
            _shdw_all_image_infos->infoArray = infoGen;
            _shdw_dyld_info_published = infoGen;

            _shdw_all_image_infos->uuidArrayCount = (uint32_t) uuidCount;

            if(uuidCount) {
                _shdw_all_image_infos->uuidArray = uuidGen;
                _shdw_dyld_uuid_published = uuidGen;
            }
            // else: count is 0, uuidArray pointer left untouched — readers see
            // zero entries regardless of what the pointer points at.

            // Atlas (v16+, iOS 11+): a second, complete serialized image table
            // published via compact_dyld_image_info_addr/size — the filtered
            // infoArray patch alone would leave it leaking every image. Zero
            // both; dyld itself signals absence with size == 0. Guarded on the
            // struct version: older dyld layouts lack these fields.
            if(_shdw_all_image_infos->version >= 16) {
                _shdw_all_image_infos->compact_dyld_image_info_addr = 0;
                _shdw_all_image_infos->compact_dyld_image_info_size = 0;
            }

            shdw_dyld_publish_task_info_mirror();

            // The filtered mirror is now live in dyld's struct; a later
            // disabled rebuild restores the originals captured above.
            _shdw_mirror_currently_patched = YES;

            vm_protect(mach_task_self(), page, vm_page_size, FALSE, _shdw_mirror_original_protection);
        } else if(!_shdw_mirror_protect_failed) {
            _shdw_mirror_protect_failed = YES;
            NSLog(@"shadow: dyld: vm_protect failed for dyld_all_image_infos, memory hiding disabled (fail soft)");
        }
    }

    pthread_mutex_unlock(&_shdw_dyld_mirror_lock);
}

void shadowhook_dyld(SHDWHookSession* hooks) {
    _shdw_dyld_collection = [NSMutableArray new];
    _shdw_dyld_add_image = [NSMutableArray new];
    _shdw_dyld_remove_image = [NSMutableArray new];
    _shdw_dyld_path_pool = [NSMutableArray new];

    // One-time-checked debug flag (FIX3): the gated add/remove NSLogs below
    // can only fire after the registrations made in this function, so the
    // flag is always initialized by the time it is read.
    gDyldDebug = getenv("SHADOW_DEBUG") != NULL;

    // Defer per-image mirror rebuilds during the replay below (the collection
    // grows by one per callback; a rebuild per image is O(N²·M) compares +
    // ~3 Mach traps each). The final rebuild after registration covers the
    // whole collection at once. Handles cache is empty at this point (no
    // hooks installed yet), so invalidation is skipped via the same flag.
    _shdw_dyld_replay_in_progress = YES;
    _dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
    _shdw_dyld_replay_in_progress = NO;
    _dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);

    // Registration above replays the current image list through the
    // callbacks, so the app-bundle spans are populated (and will be kept in
    // sync on every add/remove) before any hook below can fire.
    shdw_own_ranges_refresh();

    // These public APIs used Litehook's import-slot lane before the HK3
    // migration. Keeping them import-only avoids globally interposing dyld's
    // own calls, which can hand clients a filtered NULL header mid-load.
    [hooks hookRebindSymbol:@"_dyld_get_image_name" withReplacement:replaced_dyld_get_image_name outOldPtr:(void **) &original_dyld_get_image_name];
    [hooks hookRebindSymbol:@"_dyld_image_count" withReplacement:replaced_dyld_image_count outOldPtr:(void **) &original_dyld_image_count];
    [hooks hookRebindSymbol:@"_dyld_get_image_header" withReplacement:replaced_dyld_get_image_header outOldPtr:(void **) &original_dyld_get_image_header];
    [hooks hookRebindSymbol:@"_dyld_get_image_vmaddr_slide" withReplacement:replaced_dyld_get_image_vmaddr_slide outOldPtr:(void **) &original_dyld_get_image_vmaddr_slide];
    [hooks hookRebindSymbol:@"_dyld_register_func_for_add_image" withReplacement:replaced_dyld_register_func_for_add_image outOldPtr:(void **) &original_dyld_register_func_for_add_image];
    [hooks hookRebindSymbol:@"_dyld_register_func_for_remove_image" withReplacement:replaced_dyld_register_func_for_remove_image outOldPtr:(void **) &original_dyld_register_func_for_remove_image];
    [hooks hookRebindSymbol:@"task_info" withReplacement:replaced_task_info outOldPtr:(void **)&original_task_info];

    // TASK_DYLD_INFO is the authoritative live struct. dyld4 may expose a
    // same-named private symbol that is not the address the kernel publishes.
    task_dyld_info_data_t taskInfo = {0};
    mach_msg_type_number_t taskInfoCount = TASK_DYLD_INFO_COUNT;

    if(task_info(mach_task_self(), TASK_DYLD_INFO,
        (task_info_t)&taskInfo, &taskInfoCount) == KERN_SUCCESS
    && taskInfoCount >= TASK_DYLD_INFO_COUNT
    && taskInfo.all_image_info_addr
    && taskInfo.all_image_info_size >= sizeof(struct dyld_all_image_infos)) {
        _shdw_all_image_infos = (struct dyld_all_image_infos *)(uintptr_t)taskInfo.all_image_info_addr;
    }

    // Legacy fallback for kernels that do not publish TASK_DYLD_INFO.
    if(!_shdw_all_image_infos) {
        _shdw_all_image_infos = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
    }

    if(!_shdw_all_image_infos) {
        SHDWImageRef libdyldImage = [hooks openImage:@"/usr/lib/system/libdyld.dylib"];

        if(libdyldImage) {
            _shdw_all_image_infos = [hooks findSymbolInImage:libdyldImage symbolName:@"dyld_all_image_infos"];
            [hooks closeImage:libdyldImage];
        }
    }

    if(_shdw_all_image_infos) {
        // Intercept dyld's image-notification callback by swapping the
        // dyld_all_image_infos.notification function pointer, NOT by
        // inline-patching the notifier's code. dyld invokes the notifier
        // through this struct field (the classic gdb/lldb rendezvous), so the
        // pointer swap routes every notification through
        // replaced_dyld_image_notification, which chains to the original.
        //
        // The rejected alternative — an inline trampoline into
        // the notifier (dyld's lldb_image_notifier) — is fatal: that function
        // shares a 16KB dyld __TEXT page with hot API thunks, including
        // _dyld_get_image_name's block. Writing the trampoline COW-breaks the
        // whole page; dyld then SIGBUSes (KERN_PROTECTION_FAILURE) executing
        // the code-signing-invalidated copy the instant it calls one of those
        // thunks during launch-time dlopen initializer runs. The field lives
        // at the top of the struct (same page as its base), so one vm_protect
        // covers it; the write is a plain pointer store on arm64.
        // ponytail: arm64 (no PAC) only — on arm64e the notification field may
        // be ptrauth-signed; sign replaced_ with the field's discriminator
        // before storing. Untested there; the reproduced crash is arm64.
        if(_shdw_all_image_infos->notification) {
            mach_vm_address_t npage = (mach_vm_address_t) _shdw_all_image_infos & ~(mach_vm_address_t) (vm_page_size - 1);
            vm_prot_t nprot = VM_PROT_READ | VM_PROT_WRITE;
            vm_region_basic_info_data_64_t ninfo;
            mach_msg_type_number_t ninfo_count = VM_REGION_BASIC_INFO_COUNT_64;
            vm_address_t nregion = npage;
            vm_size_t nregion_size = 0;
            mach_port_t nobject = MACH_PORT_NULL;

            if(vm_region_64(mach_task_self(), &nregion, &nregion_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &ninfo, &ninfo_count, &nobject) == KERN_SUCCESS) {
                nprot = ninfo.protection;
            }

            if(vm_protect(mach_task_self(), npage, vm_page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
                original_dyld_image_notification = _shdw_all_image_infos->notification;
                _shdw_all_image_infos->notification = replaced_dyld_image_notification;
                vm_protect(mach_task_self(), npage, vm_page_size, FALSE, nprot);
            } else {
                NSLog(@"[Shadow] dyld notification pointer swap failed; memory hiding may be overwritten");
            }
        } else {
            NSLog(@"[Shadow] dyld debugger notification unavailable; memory hiding may be overwritten");
        }

        // Patching active: filter the arrays (initial rebuild — the collection
        // is already populated by the registration above).
        shadowhook_dyld_rebuild_dyldinfo();
        if(gDyldDebug) {
            fprintf(stderr, "[Shadow] dyld state memory=%d resolved=%p info=%p count=%u patched=%d protect_failed=%d collection=%lu\n",
                shdw_memory_hiding_enabled, _shdw_all_image_infos,
                _shdw_all_image_infos->infoArray, _shdw_all_image_infos->infoArrayCount,
                _shdw_mirror_currently_patched, _shdw_mirror_protect_failed,
                (unsigned long)[_shdw_dyld_collection count]);
        }
    } else {
        // dyld_all_image_infos unresolvable (pre-modern iOS): memory hiding
        // stays off (fail soft) — the API-level hooks above still hide images.
        NSLog(@"[Shadow] dyld_all_image_infos not found, memory hiding unavailable (fail soft)");
    }

    // Directly linkable — declared in vendor/apple/dyld_priv.h (Core.m calls
    // it the same way); no findSymbolInImage needed.
    [hooks hookRebindSymbol:@"dyld_image_path_containing_address" withReplacement:replaced_dyld_image_path_containing_address outOldPtr:(void **) &original_dyld_image_path_containing_address];
    [hooks hookRebindSymbol:@"dyld_image_header_containing_address" withReplacement:replaced_dyld_image_header_containing_address outOldPtr:(void **) &original_dyld_image_header_containing_address];

    // Address-attribution siblings (plan Wave 1c): the slide pair is ancient
    // and directly linkable; _dyld_find_unwind_sections is SJLJ-guarded (not
    // exported on armv7) and the _dyld_get_image_header_containing_address
    // alias (dyld4, iOS 15+), _dyld_get_image_uuid (iOS 10+) and
    // dyld_image_get_installname (dyld3/4) are resolved by name below so the
    // legacy (iOS 9) build doesn't link against symbols it lacks.
    [hooks hookRebindSymbol:@"_dyld_get_image_slide" withReplacement:replaced_dyld_get_image_slide outOldPtr:(void **) &original_dyld_get_image_slide];

    [hooks hookRebindSymbol:@"dlopen_preflight" withReplacement:replaced_dlopen_preflight outOldPtr:(void **) &original_dlopen_preflight];

    [hooks hookRebindSymbol:@"dlerror" withReplacement:replaced_dlerror outOldPtr:(void **) &original_dlerror];

    // Modern dyld SPIs (iOS 12+/13+). Resolved by name via findSymbolInImage: so the
    // legacy (iOS 9) build doesn't link against symbols it lacks; skipped
    // silently on OSes without them.
    SHDWImageRef libdyldImage = [hooks openImage:@"/usr/lib/system/libdyld.dylib"];

    void* findUnwindSectionsPtr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_find_unwind_sections"];

    if(findUnwindSectionsPtr) {
        [hooks hookFunction:findUnwindSectionsPtr withReplacement:replaced_dyld_find_unwind_sections outOldPtr:(void **) &original_dyld_find_unwind_sections];
    }

    void* getImageHeaderContainingAddressPtr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_get_image_header_containing_address"];

    if(getImageHeaderContainingAddressPtr) {
        [hooks hookFunction:getImageHeaderContainingAddressPtr withReplacement:replaced_dyld_image_header_containing_address outOldPtr:(void **) &original_dyld_get_image_header_containing_address];
    }

    void* getImageUuidPtr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_get_image_uuid"];

    if(getImageUuidPtr) {
        [hooks hookFunction:getImageUuidPtr withReplacement:replaced_dyld_get_image_uuid outOldPtr:(void **) &original_dyld_get_image_uuid];
    }

    void* getInstallnamePtr = [hooks findSymbolInImage:libdyldImage symbolName:@"dyld_image_get_installname"];

    if(getInstallnamePtr) {
        [hooks hookFunction:getInstallnamePtr withReplacement:replaced_dyld_image_get_installname outOldPtr:(void **) &original_dyld_image_get_installname];
    }

    void* images_for_addresses_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_images_for_addresses"];

    if(images_for_addresses_ptr) {
        [hooks hookFunction:images_for_addresses_ptr withReplacement:replaced_dyld_images_for_addresses outOldPtr:(void **) &original_dyld_images_for_addresses];
    }

    void* register_for_image_loads_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_register_for_image_loads"];

    if(register_for_image_loads_ptr) {
        shdw_real_register_for_image_loads = (void (*)(void (*)(const struct mach_header* mh, const char* path, bool unloadable))) register_for_image_loads_ptr;

        // Register our own handler with REAL dyld immediately, through the
        // raw resolved pointer — NOT through original_dyld_register_for_image_loads,
        // which is still NULL until the hook batch executes. The handler fans
        // out only visible images to every app-registered callback (the hook
        // below stores app callbacks instead of forwarding them). A static
        // guard keeps a hypothetical second shadowhook_dyld call from
        // double-registering.
        static BOOL imageLoadsHandlerRegistered = NO;

        if(!imageLoadsHandlerRegistered) {
            imageLoadsHandlerRegistered = YES;
            shdw_real_register_for_image_loads(shdw_image_load_handler);
        }

        [hooks hookFunction:register_for_image_loads_ptr withReplacement:replaced_dyld_register_for_image_loads outOldPtr:(void **) &original_dyld_register_for_image_loads];
    }

    void* register_for_bulk_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_register_for_bulk_image_loads"];

    if(register_for_bulk_ptr) {
        shdw_real_register_for_bulk_image_loads = (void (*)(void (*)(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]))) register_for_bulk_ptr;

        // Same as above: register the bulk handler with real dyld through the
        // raw resolved pointer, once, before the hook is queued.
        static BOOL bulkLoadsHandlerRegistered = NO;

        if(!bulkLoadsHandlerRegistered) {
            bulkLoadsHandlerRegistered = YES;
            shdw_real_register_for_bulk_image_loads(shdw_bulk_load_handler);
        }

        [hooks hookFunction:register_for_bulk_ptr withReplacement:replaced_dyld_register_for_bulk_image_loads outOldPtr:(void **) &original_dyld_register_for_bulk_image_loads];
    }

    // ObjC-mapped notifier SPIs (plan Wave 1c): _dyld_objc_notify_register
    // (vendored dyld_priv.h; libdyld export on modern iOS) and
    // objc_addLoadImageFunc (iOS 15+; resolved by name — not in the vendored
    // headers). Hooked so external registrants receive the filtered fan-out
    // only (see the replacement bodies). No handler is registered with real
    // _dyld_objc_notify_register here — dyld keeps a single objc-notifier
    // slot and would overwrite libobjc's registration; the fan-out is driven
    // from the image-load/remove-image handlers instead.
    void* objc_notify_register_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_objc_notify_register"];

    if(objc_notify_register_ptr) {
        [hooks hookFunction:objc_notify_register_ptr withReplacement:replaced_dyld_objc_notify_register outOldPtr:(void **) &original_dyld_objc_notify_register];
    }

    void* objc_add_load_image_ptr = dlsym(RTLD_DEFAULT, "objc_addLoadImageFunc");

    if(objc_add_load_image_ptr) {
        [hooks hookFunction:objc_add_load_image_ptr withReplacement:replaced_objc_addLoadImageFunc outOldPtr:(void **) &original_objc_addLoadImageFunc];
    }

    // Process-snapshot SPI (plan Wave 1c): opaque handles; external callers
    // get the NULL "no process info" state (see the replacement bodies).
    // Resolved by name; skipped silently on OSes lacking the exports.
    void* process_info_create_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_process_info_create"];

    if(process_info_create_ptr) {
        [hooks hookFunction:process_info_create_ptr withReplacement:replaced_dyld_process_info_create outOldPtr:(void **) &original_dyld_process_info_create];
    }

    void* process_info_get_images_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_process_info_get_images"];

    if(process_info_get_images_ptr) {
        [hooks hookFunction:process_info_get_images_ptr withReplacement:replaced_dyld_process_info_get_images outOldPtr:(void **) &original_dyld_process_info_get_images];
    }

    void* process_info_destroy_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_process_info_destroy"];

    if(process_info_destroy_ptr) {
        [hooks hookFunction:process_info_destroy_ptr withReplacement:replaced_dyld_process_info_destroy outOldPtr:(void **) &original_dyld_process_info_destroy];
    }

    // dyld4-era accessor names (iOS 15+); resolved by name, skipped silently
    // on OSes without them — same discipline as the legacy destroy above.
    void* process_info_get_state_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_process_info_get_state"];

    if(process_info_get_state_ptr) {
        [hooks hookFunction:process_info_get_state_ptr withReplacement:replaced_dyld_process_info_get_state outOldPtr:(void **) &original_dyld_process_info_get_state];
    }

    void* process_info_get_image_path_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_process_info_get_image_path"];

    if(process_info_get_image_path_ptr) {
        [hooks hookFunction:process_info_get_image_path_ptr withReplacement:replaced_dyld_process_info_get_image_path outOldPtr:(void **) &original_dyld_process_info_get_image_path];
    }

    void* process_info_get_image_uuid_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_process_info_get_image_uuid"];

    if(process_info_get_image_uuid_ptr) {
        [hooks hookFunction:process_info_get_image_uuid_ptr withReplacement:replaced_dyld_process_info_get_image_uuid outOldPtr:(void **) &original_dyld_process_info_get_image_uuid];
    }

    void* process_info_release_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"_dyld_process_info_release"];

    if(process_info_release_ptr) {
        [hooks hookFunction:process_info_release_ptr withReplacement:replaced_dyld_process_info_release outOldPtr:(void **) &original_dyld_process_info_release];
    }

    if(libdyldImage) {
        [hooks closeImage:libdyldImage];
    }

    // Legacy NS* image/symbol lookup APIs (plan Wave 1c): __API_UNAVAILABLE
    // on iOS in the SDK, resolved by name — skipped silently on OSes that
    // never exported them (modern iOS).
    void* nsaddimage_ptr = dlsym(RTLD_DEFAULT, "NSAddImage");

    if(nsaddimage_ptr) {
        [hooks hookFunction:nsaddimage_ptr withReplacement:replaced_NSAddImage outOldPtr:(void **) &original_NSAddImage];
    }

    void* nslookupsymbol_ptr = dlsym(RTLD_DEFAULT, "NSLookupSymbolInImage");

    if(nslookupsymbol_ptr) {
        [hooks hookFunction:nslookupsymbol_ptr withReplacement:replaced_NSLookupSymbolInImage outOldPtr:(void **) &original_NSLookupSymbolInImage];
    }

    void* nsversion_ptr = dlsym(RTLD_DEFAULT, "NSVersionOfRunTimeLibrary");

    if(nsversion_ptr) {
        [hooks hookFunction:nsversion_ptr withReplacement:replaced_NSVersionOfRunTimeLibrary outOldPtr:(void **) &original_NSVersionOfRunTimeLibrary];
    }
}

void shadowhook_dyld_extra(SHDWHookSession* hooks) {
    // dlopen hook code from Choicy
    SHDWImageRef libdyldImage = [hooks openImage:@"/usr/lib/system/libdyld.dylib"];
    // libdyld is always loaded (it IS the dyld library); RTLD_NOLOAD returns
    // the existing handle without a fresh load. A plain dlopen here would
    // fire the dyld add-image callback (shadowhook_dyld_updatelibs) on this
    // install thread, whose image-list walk re-enters the hooked
    // _dyld_image_count/_dyld_get_image_name and recurses (observed: launch
    // hang, 9k+ updatelibs(add) libdyld cycles).
    void* libdyldHandle = dlopen("/usr/lib/system/libdyld.dylib", RTLD_NOLOAD | RTLD_NOW);
    void* dlopen_global_var_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"__ZN5dyld45gDyldE"];

    [hooks hookRebindSymbol:@"dlopen" withReplacement:replaced_dlopen outOldPtr:(void **) &original_dlopen];

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_14_1 && !dlopen_global_var_ptr) {
        void* dlopen_internal_ptr = [hooks findSymbolInImage:libdyldImage symbolName:@"__ZL15dlopen_internalPKciPv"];

        if(dlopen_internal_ptr) {
            [hooks hookFunction:dlopen_internal_ptr withReplacement:replaced_dlopen_internal outOldPtr:(void **) &original_dlopen_internal];
        }
    } else {
        void* dlopen_from_ptr = dlsym(libdyldHandle, "dlopen_from");

        if(dlopen_from_ptr) {
            [hooks hookFunction:dlopen_from_ptr withReplacement:replaced_dlopen_internal outOldPtr:(void **) &original_dlopen_internal];
        }
    }

    if(libdyldImage) {
        [hooks closeImage:libdyldImage];
    }
}

void shadowhook_dyld_symlookup(SHDWHookSession* hooks) {
    // dlsym is a tiny shared-cache entrypoint on some iOS releases and may
    // not have a relocatable prologue. Cover normal callers through their
    // import slots when the entrypoint hook cannot be installed.
    if(![hooks hookFunction:dlsym withReplacement:replaced_dlsym outOldPtr:(void **) &original_dlsym]) {
        [hooks hookRebindSymbol:@"dlsym" withReplacement:replaced_dlsym outOldPtr:(void **) &original_dlsym];
    }

    // CFBundle symbol-resolution wrappers (plan Wave 3): same bypass surface
    // as dlsym, reached through CoreFoundation.
    [hooks hookFunction:CFBundleGetFunctionPointerForName withReplacement:replaced_CFBundleGetFunctionPointerForName outOldPtr:(void **) &original_CFBundleGetFunctionPointerForName];
    [hooks hookFunction:CFBundleGetFunctionPointersForNames withReplacement:replaced_CFBundleGetFunctionPointersForNames outOldPtr:(void **) &original_CFBundleGetFunctionPointersForNames];
    [hooks hookFunction:CFBundleGetDataPointerForName withReplacement:replaced_CFBundleGetDataPointerForName outOldPtr:(void **) &original_CFBundleGetDataPointerForName];
}

void shadowhook_dyld_symaddrlookup(SHDWHookSession* hooks) {
    [hooks hookFunction:dladdr withReplacement:replaced_dladdr outOldPtr:(void **) &original_dladdr];
}

void shadowhook_dyld_verify(void) {
    // The findSymbolInImage/dlsym-resolved SPIs (unwind sections, image
    // uuid, process info, NS* lookups, register-for-image-loads) are
    // excluded — NULL is expected when the OS lacks the export.
    shdw_hook_check_t checks[] = {
        { "_dyld_get_image_name", original_dyld_get_image_name },
        { "_dyld_image_count", original_dyld_image_count },
        { "_dyld_get_image_header", original_dyld_get_image_header },
        { "_dyld_get_image_vmaddr_slide", original_dyld_get_image_vmaddr_slide },
        { "_dyld_register_func_for_add_image", original_dyld_register_func_for_add_image },
        { "_dyld_register_func_for_remove_image", original_dyld_register_func_for_remove_image },
        { "dyld_image_path_containing_address", original_dyld_image_path_containing_address },
        { "dyld_image_header_containing_address", original_dyld_image_header_containing_address },
        { "_dyld_get_image_slide", original_dyld_get_image_slide },
        { "dlopen_preflight", original_dlopen_preflight },
        { "dlerror", original_dlerror },
        { "task_info", original_task_info },
    };

    shdw_verify_hooks("dyld", checks, sizeof(checks) / sizeof(checks[0]));
}

void shadowhook_dyld_extra_verify(void) {
    // dlopen_internal/dlopen_from resolve conditionally by OS version;
    // excluded here.
    shdw_hook_check_t checks[] = {
        { "dlopen", original_dlopen },
    };

    shdw_verify_hooks("dyld_extra", checks, sizeof(checks) / sizeof(checks[0]));
}

void shadowhook_dyld_symlookup_verify(void) {
    shdw_hook_check_t checks[] = {
        { "dlsym", original_dlsym },
        { "CFBundleGetFunctionPointerForName", original_CFBundleGetFunctionPointerForName },
        { "CFBundleGetFunctionPointersForNames", original_CFBundleGetFunctionPointersForNames },
        { "CFBundleGetDataPointerForName", original_CFBundleGetDataPointerForName },
    };

    shdw_verify_hooks("dyld_symlookup", checks, sizeof(checks) / sizeof(checks[0]));
}

void shadowhook_dyld_symaddrlookup_verify(void) {
    shdw_hook_check_t checks[] = {
        { "dladdr", original_dladdr },
    };

    shdw_verify_hooks("dyld_symaddrlookup", checks, sizeof(checks) / sizeof(checks[0]));
}
