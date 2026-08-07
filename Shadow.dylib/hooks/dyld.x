#import "hooks.h"
#import <RootBridge.h>
#import <os/lock.h>
#import <mach/vm_region.h>

static NSMutableArray<NSDictionary *>* _shdw_dyld_collection = nil;
static NSMutableArray<NSValue *>* _shdw_dyld_add_image = nil;
static NSMutableArray<NSValue *>* _shdw_dyld_remove_image = nil;
static BOOL _shdw_dyld_error = NO;
// static NSOperationQueue* _shdw_dyld_queue = nil;
// NSMutableData* _shdw_dyld_task_dyld_info = nil;

// Real dyld_all_image_infos global (resolved in shadowhook_dyld). When set,
// we patch its arrays directly. When NULL (very old iOS), memory hiding stays
// off (fail soft); the API-level enumeration hooks still hide images.
static struct dyld_all_image_infos* _shdw_all_image_infos = NULL;

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
// `_shdw_dyld_path_pool` for the lifetime of the process so
// fileSystemRepresentation pointers never dangle after a collection removal.
#define SHADOW_DYLD_MIRROR_CAPACITY 4096   // beyond any real process's image count

static os_unfair_lock _shdw_dyld_mirror_lock = OS_UNFAIR_LOCK_INIT;
static struct dyld_image_info* _shdw_dyld_info_buffers[2] = {NULL, NULL};
static struct dyld_image_info* _shdw_dyld_info_published = NULL;
static struct dyld_uuid_info* _shdw_dyld_uuid_buffers[2] = {NULL, NULL};
static struct dyld_uuid_info* _shdw_dyld_uuid_published = NULL;
static NSMutableArray* _shdw_dyld_path_pool = nil;

// dyld's original uuid array, captured before our first patch overwrites the
// struct's uuidArray pointer (later rebuilds must scan the original, not our
// own filtered mirror, or new image uuids would never appear).
static const struct dyld_uuid_info* _shdw_real_uuid_array = NULL;
static uintptr_t _shdw_real_uuid_count = 0;

// App-bundle image spans for shdw_caller_is_tweak() (see hooks.h). Rebuilt
// from the dyld image list whenever it changes and once at install; the
// writer serializes on `_shdw_own_ranges_lock` and publishes with one
// release store, so readers (no lock, one acquire load) never see a torn or
// half-built snapshot.
shdw_own_ranges_t _shdw_own_ranges_a;
shdw_own_ranges_t _shdw_own_ranges_b;
shdw_own_ranges_t* _shdw_own_ranges_published = &_shdw_own_ranges_a;
static os_unfair_lock _shdw_own_ranges_lock = OS_UNFAIR_LOCK_INIT;

void shdw_own_ranges_refresh(void) {
    os_unfair_lock_lock(&_shdw_own_ranges_lock);

    shdw_own_ranges_t* published = __atomic_load_n(&_shdw_own_ranges_published, __ATOMIC_ACQUIRE);
    shdw_own_ranges_t* other = (published == &_shdw_own_ranges_a) ? &_shdw_own_ranges_b : &_shdw_own_ranges_a;

    shdw_own_ranges_t rebuilt = { .count = 0 };
    const char* bundle = [[shdw_shadow_instance() bundlePath] fileSystemRepresentation];

    uint32_t count = _dyld_image_count();

    for(uint32_t i = 0; i < count && rebuilt.count < SHADOW_OWN_IMAGE_MAX; i++) {
        const char* path = _dyld_get_image_name(i);

        // Same substring predicate -[Shadow isAddrExternal:] applied per call.
        if(!path || !strstr(path, bundle)) {
            continue;
        }

        const struct mach_header* mh = _dyld_get_image_header(i);

        if(!mh || mh->magic != MH_MAGIC_64) {
            continue;
        }

        // Union span across all segments (return addresses only land in
        // executable code, so the loose union is exact for our purposes).
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
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

        if(end > base) {
            rebuilt.range[rebuilt.count++] = (shdw_range_t){ .base = base, .end = end };
        }
    }

    *other = rebuilt;
    __atomic_store_n(&_shdw_own_ranges_published, other, __ATOMIC_RELEASE);

    os_unfair_lock_unlock(&_shdw_own_ranges_lock);
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

// Feature flag: "MemoryLevelHiding" in Shadow's prefs plist (default OFF).
// SHADOW_PREFS_PLIST tracks the bundle id (me.jjolano.shadow); on rootless the
// plist lives under /var/jb, so try both paths. A missing/unreadable plist
// simply means the flag is off — memory hiding must never break the hook.
// Per-app settings win: the plist holds a per-app dict keyed by bundle id
// (see ShadowSettings getPreferencesForIdentifier — App_Enabled plus the same
// hook keys), falling back to the top-level key. Re-read per call so settings
// changes apply without a respring; the plist read is cheap and the
// detector-escalation check above already runs per call.
static BOOL shdw_dyld_memory_hiding_enabled(void) {
    // Escalation: when a detection library is present, memory hiding forces
    // on regardless of the prefs flag (set by dylib.x before hooks install).
    if(shdw_detector_present) {
        return YES;
    }

    NSDictionary* prefs = nil;

    for(NSString* path in @[
        [RootBridge getJBPath:@(SHADOW_PREFS_PLIST)],
        @(SHADOW_PREFS_PLIST)
    ]) {
        prefs = [NSDictionary dictionaryWithContentsOfFile:path];

        if(prefs) {
            break;
        }
    }

    if(!prefs) {
        return NO;
    }

    // Per-app dict (when the app is enabled there) overrides the global key.
    NSString* bundleIdentifier = [Shadow getBundleIdentifier];

    if(bundleIdentifier) {
        NSDictionary* appPrefs = prefs[bundleIdentifier];

        if([appPrefs isKindOfClass:[NSDictionary class]] && [appPrefs[@"App_Enabled"] boolValue]) {
            return [appPrefs[@"MemoryLevelHiding"] boolValue];
        }
    }

    return [prefs[@"MemoryLevelHiding"] boolValue];
}

static void shadowhook_dyld_rebuild_dyldinfo(void);

// todo: maybe hook this private symbol
// extern void call_funcs_for_add_image(struct mach_header *mh, unsigned long vmaddr_slide);

// Locked snapshot access for the hot accessors: the snapshot is rebuilt
// under `_shdw_dyld_mirror_lock`, so reading it under the same lock can
// never observe a torn or mismatched entry (an uncontended unfair lock is a
// few ns — nothing compared to the array copies this replaced). Returns NULL
// when no snapshot has ever been published (allocation failed); callers then
// fall back to the old collection path.
static shdw_dyld_snapshot_t* shdw_dyld_snapshot_begin(void) {
    os_unfair_lock_lock(&_shdw_dyld_mirror_lock);
    return _shdw_dyld_snapshot;
}

static void shdw_dyld_snapshot_end(void) {
    os_unfair_lock_unlock(&_shdw_dyld_mirror_lock);
}

static uint32_t (*original_dyld_image_count)();
static uint32_t replaced_dyld_image_count() {
    if(isCallerTweak()) {
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
    if(isCallerTweak()) {
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
    if(isCallerTweak()) {
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
    if(isCallerTweak()) {
        return original_dyld_get_image_name(image_index);
    }

    shdw_dyld_snapshot_t* snapshot = shdw_dyld_snapshot_begin();

    if(!snapshot) {
        NSArray* collection = [_shdw_dyld_collection copy];
        shdw_dyld_snapshot_end();
        return image_index < [collection count] ? [collection[image_index][@"name"] fileSystemRepresentation] : NULL;
    }

    const char* name = image_index < snapshot->count ? snapshot->entry[image_index].name : NULL;
    shdw_dyld_snapshot_end();
    return name;
}

// _dyld_image_path_containing_address is called directly by commercial
// detection SDKs (bypasses dyld API filtering) AND by Shadow's own Core.m
// (isAddrExternal/isAddrRestricted). Return truth to the tweak's own callers,
// lie (executable path) to everyone else.
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

    // Is the CALLER of this hook inside the tweak? (not the addr arg)
    BOOL caller_is_tweak = shdw_caller_is_tweak(__builtin_return_address(0));

    _shdw_dyipca_in_hook = NO;

    if(caller_is_tweak) {
        return original_dyld_image_path_containing_address(addr);
    }

    const char* result = original_dyld_image_path_containing_address(addr);

    if(result && [_shadow isCPathRestricted:result]) {
        return [[Shadow getExecutablePath] fileSystemRepresentation];
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

    // Is the CALLER of this hook inside the app bundle (app code or an
    // embedded detection framework)? Not the addr arg. Non-embedded callers
    // (the tweak itself, other injected dylibs) pass through untouched.
    BOOL caller_outside_app = shdw_caller_is_tweak(__builtin_return_address(0));

    _shdw_dyighca_in_hook = NO;

    if(caller_outside_app) {
        return original_dyld_image_header_containing_address(addr);
    }

    // Embedded caller probing a filtered image's address: report no image.
    if([_shadow isAddrRestricted:addr]) {
        return NULL;
    }

    return original_dyld_image_header_containing_address(addr);
}

static void* (*original_dlopen)(const char* path, int mode);
static void* replaced_dlopen(const char* path, int mode) {
    if(isCallerTweak() || !path) {
        return original_dlopen(path, mode);
    }

    if(path[0] != '/') {
        if(![_shadow isPathRestricted:@(path) options:@{
            kShadowRestrictionWorkingDir : [RootBridge getJBPath:@"/usr/lib"],
            kShadowRestrictionFileExtension : @"dylib"
            }]) {
            return original_dlopen(path, mode);
        }
    } else {
        if(![_shadow isCPathRestricted:path]) {
            return original_dlopen(path, mode);
        }
    }

    // A non-tweak caller trying to dlopen a jailbreak dylib is a probe.
    shdw_detector_detected("dlopen");

    _shdw_dyld_error = YES;
    return NULL;
}

static void* (*original_dlopen_internal)(const char* path, int mode, void* caller);
static void* replaced_dlopen_internal(const char* path, int mode, void* caller) {
    if(isCallerTweak() || !path) {
        return original_dlopen_internal(path, mode, caller);
    }

    if(path[0] != '/') {
        if(![_shadow isPathRestricted:@(path) options:@{
            kShadowRestrictionWorkingDir : [RootBridge getJBPath:@"/usr/lib"],
            kShadowRestrictionFileExtension : @"dylib"
            }]) {
            return original_dlopen_internal(path, mode, caller);
        }
    } else {
        if(![_shadow isCPathRestricted:path]) {
            return original_dlopen_internal(path, mode, caller);
        }
    }

    shdw_detector_detected("dlopen");

    _shdw_dyld_error = YES;
    return NULL;
}

static bool (*original_dlopen_preflight)(const char* path);
static bool replaced_dlopen_preflight(const char* path) {
    if(isCallerTweak() || !path) {
        return original_dlopen_preflight(path);
    }

    if(path[0] != '/') {
        if(![_shadow isPathRestricted:@(path) options:@{
            kShadowRestrictionWorkingDir : [RootBridge getJBPath:@"/usr/lib"],
            kShadowRestrictionFileExtension : @"dylib"
            }]) {
            return original_dlopen_preflight(path);
        }
    } else {
        if(![_shadow isCPathRestricted:path]) {
            return original_dlopen_preflight(path);
        }
    }

    shdw_detector_detected("dlopen");

    return false;
}

static void (*original_dyld_register_func_for_add_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if(isCallerTweak() || !func) {
        return original_dyld_register_func_for_add_image(func);
    }

    // add to our collection
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
    if(isCallerTweak() || !func) {
        return original_dyld_register_func_for_remove_image(func);
    }

    [_shdw_dyld_remove_image addObject:[NSValue valueWithPointer:func]];
}

void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!mh) {
        return;
    }

    // The dyld image list changed: refresh the app-bundle spans.
    shdw_own_ranges_refresh();

    const char* image_path = dyld_image_path_containing_address(mh);

    // Add if safe dylib.
    if(image_path) {
        NSString* path = [NSString stringWithUTF8String:image_path];

        if([path hasPrefix:@"/System"] || ![_shadow isPathRestricted:path options:@{kShadowRestrictionEnableResolve : @(NO)}]) {
            NSLog(@"%@: %@: %@", @"dyld", @"adding lib", path);

            [_shdw_dyld_collection addObject:@{
                @"name" : path,
                @"mach_header" : [NSValue valueWithPointer:mh],
                @"slide" : [NSValue valueWithPointer:(void *)vmaddr_slide]
            }];

            // Retain the path for the mirror's imageFilePath pointers (the
            // collection may release it again on remove).
            [_shdw_dyld_path_pool addObject:path];

            // Keep dyld_all_image_infos filtered arrays in sync.
            shadowhook_dyld_rebuild_dyldinfo();

            // Call event handlers.
            NSArray* _dyld_add_image = [_shdw_dyld_add_image copy];

            if([_dyld_add_image count]) {
                NSLog(@"%@: %@", @"dyld", @"add_image calling handlers");

                for(NSValue* func_ptr in _dyld_add_image) {
                    void (*func)(const struct mach_header*, intptr_t) = [func_ptr pointerValue];
                    func(mh, vmaddr_slide);
                }
            }
        }
    }
}

void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!mh) {
        return;
    }

    // The dyld image list changed: refresh the app-bundle spans.
    shdw_own_ranges_refresh();

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
        NSLog(@"%@: %@: %@", @"dyld", @"removing lib", dylibToRemove[@"name"]);
        [_shdw_dyld_collection removeObject:dylibToRemove];

        // Keep dyld_all_image_infos filtered arrays in sync.
        shadowhook_dyld_rebuild_dyldinfo();

        // Call event handlers.
        NSArray* _dyld_remove_image = [_shdw_dyld_remove_image copy];

        if([_dyld_remove_image count]) {
            NSLog(@"%@: %@", @"dyld", @"remove_image calling handlers");
            
            for(NSValue* func_ptr in _dyld_remove_image) {
                void (*func)(const struct mach_header*, intptr_t) = [func_ptr pointerValue];
                func(mh, vmaddr_slide);
            }
        }
    }
}

static char* (*original_dlerror)(void);
static char* replaced_dlerror(void) {
    if(isCallerTweak() || !_shdw_dyld_error) {
        return original_dlerror();
    }

    _shdw_dyld_error = NO;
    return "library not found";
}

static void* (*original_dlsym)(void* handle, const char* symbol);
static void* replaced_dlsym(void* handle, const char* symbol) {
    if(isCallerTweak()) {
        return original_dlsym(handle, symbol);
    }

    void* addr = original_dlsym(handle, symbol);

    if(![_shadow isAddrRestricted:addr]) {
        return addr;
    }

    if(symbol) {
        NSLog(@"%@: %@: %s", @"dlsym", @"restricted symbol lookup", symbol);
    }

    // A non-tweak caller resolving a jailbreak symbol is a probe.
    shdw_detector_detected("dlsym");

    _shdw_dyld_error = YES;
    return NULL;
}

static int (*original_dladdr)(const void* addr, Dl_info* info);
static int replaced_dladdr(const void* addr, Dl_info* info) {
    if(isCallerTweak()) {
        return original_dladdr(addr, info);
    }

    int result = original_dladdr(addr, info);

    if(result && [_shadow isAddrRestricted:addr]) {
        if(info) {
            // Capture the symbol name before zeroing: the re-lookup below
            // needs it, but the record's fbase/saddr must not survive — they
            // would leak the hidden image's load address to a detector
            // reading the untouched fields.
            const char* symbolName = info->dli_sname;

            // Zero the whole record; the executable-path fallback below is
            // the only thing a detector may read.
            memset(info, 0, sizeof(Dl_info));

            // One lookup only: dlsym with identical args returns the same
            // result every time, so if it resolves to a restricted address
            // the old loop would spin forever — apply the executable-name
            // fallback immediately instead. A NULL symbol name skips the
            // lookup (goes straight to the fallback).
            if(symbolName) {
                void* sym = dlsym(RTLD_NEXT, symbolName);

                if(sym && ![_shadow isAddrRestricted:sym]) {
                    return original_dladdr(sym, info);
                }
            }

            // as a fallback, we'll just say this addr is part of the executable itself
            info->dli_fname = [[Shadow getExecutablePath] fileSystemRepresentation];
        }
    }

    return result;
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
// "unknown" signal to addresses inside hidden images so stack-backtrace
// symbolication can't walk past the dyld API filter.
static void (*original_dyld_images_for_addresses)(unsigned count, const void* addresses[], struct dyld_image_uuid_offset infos[]);
static void replaced_dyld_images_for_addresses(unsigned count, const void* addresses[], struct dyld_image_uuid_offset infos[]) {
    if(isCallerTweak()) {
        return original_dyld_images_for_addresses(count, addresses, infos);
    }

    original_dyld_images_for_addresses(count, addresses, infos);

    if(!infos) {
        return;
    }

    for(unsigned i = 0; i < count; i++) {
        if(shdw_dyld_image_is_hidden(infos[i].image)) {
            memset(&infos[i], 0, sizeof(infos[i]));
        }
    }
}

// iOS 12+ SPI: register a per-load callback (replays currently-loaded images
// at registration). Same fan-out pattern as the add_image registration above:
// app callbacks are stored in slots, and our own handler — registered with
// real dyld at hook-install time — delivers only visible images, so a hidden
// image never reaches a detector's callback, even on later loads.
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
}
static void (*original_dyld_register_for_image_loads)(void (*func)(const struct mach_header* mh, const char* path, bool unloadable));
static void replaced_dyld_register_for_image_loads(void (*func)(const struct mach_header* mh, const char* path, bool unloadable)) {
    if(isCallerTweak() || !func) {
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
    if(isCallerTweak() || !func) {
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

// Real dyld function pointers for the modern load/bulk-registration SPIs,
// resolved by name from libdyld in shadowhook_dyld. The internal handlers
// (shdw_image_load_handler / shdw_bulk_load_handler) MUST be registered with
// real dyld through these raw pointers, not through the MSHookFunction
// out-params (original_dyld_register_*): those are only filled when the hook
// batch executes (dylib.x queues first), so calling them at install time
// would call NULL and crash.
static void (*shdw_real_register_for_image_loads)(void (*func)(const struct mach_header* mh, const char* path, bool unloadable));
static void (*shdw_real_register_for_bulk_image_loads)(void (*func)(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]));

static void shadowhook_dyld_rebuild_dyldinfo(void) {
    os_unfair_lock_lock(&_shdw_dyld_mirror_lock);

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    NSUInteger count = MIN([_dyld_collection count], SHADOW_DYLD_MIRROR_CAPACITY);

    // C4: refresh the hot-path snapshot (always, even when the memory-hiding
    // mirrors below are disabled). Fill the inactive buffer, then publish it.
    // On allocation failure nothing is published — the previously published
    // snapshot (or none) stays in place, and the accessors fall back to the
    // collection until the first successful publish. Readers take this lock
    // (see the accessors), so the publish needs no atomics; kept as one
    // anyway for clarity.
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
            snapshot->entry[i].name = [dylib[@"name"] fileSystemRepresentation];
        }

        __atomic_store_n(&_shdw_dyld_snapshot, snapshot, __ATOMIC_RELEASE);
    }

    // No struct to patch (pre-modern iOS): memory hiding stays off (fail
    // soft); the API-level enumeration hooks above still hide images.
    if(!_shdw_all_image_infos) {
        os_unfair_lock_unlock(&_shdw_dyld_mirror_lock);
        return;
    }

    // Feature-flagged (default OFF): leave dyld's real data alone entirely.
    if(!shdw_dyld_memory_hiding_enabled()) {
        os_unfair_lock_unlock(&_shdw_dyld_mirror_lock);
        return;
    }

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

    // Capture dyld's real uuid array once, before our patch overwrites the
    // struct's uuidArray pointer (later rebuilds must scan the original, not
    // our own filtered mirror, or new image uuids would never appear).
    if(!_shdw_real_uuid_array) {
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
            infoGen[i].imageFilePath = [dylib[@"name"] fileSystemRepresentation];

            // ponytail: imageFileModDate is unused by detection suites; they only walk names/counts
            infoGen[i].imageFileModDate = 0;
        }

        // Filtered uuid array: keep dyld's own uuid entries whose load address
        // matches the collection, in collection order. dyld's uuidArray is not
        // touched; we just re-scan the original (captured once) on every rebuild.
        NSUInteger uuidCount = 0;

        if(_shdw_real_uuid_array && _shdw_real_uuid_count) {
            for(NSUInteger i = 0; i < count; i++) {
                const struct mach_header* mh = (struct mach_header *)[_dyld_collection[i][@"mach_header"] pointerValue];

                for(uintptr_t j = 0; j < _shdw_real_uuid_count; j++) {
                    if(_shdw_real_uuid_array[j].imageLoadAddress == mh) {
                        uuidGen[uuidCount].imageLoadAddress = mh;
                        memcpy(uuidGen[uuidCount].imageUUID, _shdw_real_uuid_array[j].imageUUID, sizeof(uuid_t));
                        uuidCount++;
                        break;
                    }
                }
            }
        }

        // Publish into dyld's live struct (plain, non-PAC-signed pointers). The
        // page may be read-only: make it writable via vm_protect, write only
        // the four array fields, then restore the original protection. On
        // failure we log once and keep the previous state (fail soft).
        static BOOL protectFailed = NO;
        static vm_prot_t originalProtection = VM_PROT_READ | VM_PROT_WRITE;
        mach_vm_address_t page = (mach_vm_address_t) _shdw_all_image_infos & ~(mach_vm_address_t) (vm_page_size - 1);

        if(!protectFailed) {
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
            vm_address_t region = page;
            vm_size_t region_size = 0;
            mach_port_t object_name = MACH_PORT_NULL;

            if(vm_region_64(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &info_count, &object_name) == KERN_SUCCESS) {
                originalProtection = info.protection;
            }
        }

        if(!protectFailed && vm_protect(mach_task_self(), page, vm_page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE) == KERN_SUCCESS) {
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

            vm_protect(mach_task_self(), page, vm_page_size, FALSE, originalProtection);
        } else if(!protectFailed) {
            protectFailed = YES;
            NSLog(@"shadow: dyld: vm_protect failed for dyld_all_image_infos, memory hiding disabled (fail soft)");
        }
    }

    os_unfair_lock_unlock(&_shdw_dyld_mirror_lock);
}

void shadowhook_dyld(HKSubstitutor* hooks) {
    _shdw_dyld_collection = [NSMutableArray new];
    _shdw_dyld_add_image = [NSMutableArray new];
    _shdw_dyld_remove_image = [NSMutableArray new];
    _shdw_dyld_path_pool = [NSMutableArray new];

    _dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
    _dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);

    // Registration above replays the current image list through the
    // callbacks, so the app-bundle spans are populated (and will be kept in
    // sync on every add/remove) before any hook below can fire.
    shdw_own_ranges_refresh();

    MSHookFunction(_dyld_get_image_name, replaced_dyld_get_image_name, (void **) &original_dyld_get_image_name);
    MSHookFunction(_dyld_image_count, replaced_dyld_image_count, (void **) &original_dyld_image_count);
    MSHookFunction(_dyld_get_image_header, replaced_dyld_get_image_header, (void **) &original_dyld_get_image_header);
    MSHookFunction(_dyld_get_image_vmaddr_slide, replaced_dyld_get_image_vmaddr_slide, (void **) &original_dyld_get_image_vmaddr_slide);
    MSHookFunction(_dyld_register_func_for_add_image, replaced_dyld_register_func_for_add_image, (void **) &original_dyld_register_func_for_add_image);
    MSHookFunction(_dyld_register_func_for_remove_image, replaced_dyld_register_func_for_remove_image, (void **) &original_dyld_register_func_for_remove_image);

    // Resolve the exported dyld_all_image_infos global so we can patch its
    // arrays directly.
    _shdw_all_image_infos = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");

    if(!_shdw_all_image_infos) {
        MSImageRef libdyldImage = MSGetImageByName("/usr/lib/system/libdyld.dylib");

        if(libdyldImage) {
            _shdw_all_image_infos = MSFindSymbol(libdyldImage, "dyld_all_image_infos");
        }
    }

    if(_shdw_all_image_infos) {
        // Patching active: filter the arrays (initial rebuild — the collection
        // is already populated by the registration above).
        shadowhook_dyld_rebuild_dyldinfo();
    } else {
        // dyld_all_image_infos unresolvable (pre-modern iOS): memory hiding
        // stays off (fail soft) — the API-level hooks above still hide images.
        NSLog(@"[Shadow] dyld_all_image_infos not found, memory hiding unavailable (fail soft)");
    }

    // Directly linkable — declared in vendor/apple/dyld_priv.h (Core.m calls
    // it the same way); no MSFindSymbol needed.
    MSHookFunction(dyld_image_path_containing_address, replaced_dyld_image_path_containing_address, (void **) &original_dyld_image_path_containing_address);
    MSHookFunction(dyld_image_header_containing_address, replaced_dyld_image_header_containing_address, (void **) &original_dyld_image_header_containing_address);

    MSHookFunction(dlopen_preflight, replaced_dlopen_preflight, (void **) &original_dlopen_preflight);

    MSHookFunction(dlerror, replaced_dlerror, (void **) &original_dlerror);

    // Modern dyld SPIs (iOS 12+/13+). Resolved by name via MSFindSymbol so the
    // legacy (iOS 9) build doesn't link against symbols it lacks; skipped
    // silently on OSes without them.
    MSImageRef libdyldImage = MSGetImageByName("/usr/lib/system/libdyld.dylib");

    void* images_for_addresses_ptr = MSFindSymbol(libdyldImage, "_dyld_images_for_addresses");

    if(images_for_addresses_ptr) {
        MSHookFunction(images_for_addresses_ptr, replaced_dyld_images_for_addresses, (void **) &original_dyld_images_for_addresses);
    }

    void* register_for_image_loads_ptr = MSFindSymbol(libdyldImage, "_dyld_register_for_image_loads");

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

        MSHookFunction(register_for_image_loads_ptr, replaced_dyld_register_for_image_loads, (void **) &original_dyld_register_for_image_loads);
    }

    void* register_for_bulk_ptr = MSFindSymbol(libdyldImage, "_dyld_register_for_bulk_image_loads");

    if(register_for_bulk_ptr) {
        shdw_real_register_for_bulk_image_loads = (void (*)(void (*)(unsigned imageCount, const struct mach_header* mhs[], const char* paths[]))) register_for_bulk_ptr;

        // Same as above: register the bulk handler with real dyld through the
        // raw resolved pointer, once, before the hook is queued.
        static BOOL bulkLoadsHandlerRegistered = NO;

        if(!bulkLoadsHandlerRegistered) {
            bulkLoadsHandlerRegistered = YES;
            shdw_real_register_for_bulk_image_loads(shdw_bulk_load_handler);
        }

        MSHookFunction(register_for_bulk_ptr, replaced_dyld_register_for_bulk_image_loads, (void **) &original_dyld_register_for_bulk_image_loads);
    }
}

void shadowhook_dyld_extra(HKSubstitutor* hooks) {
    // dlopen hook code from Choicy
    MSImageRef libdyldImage = MSGetImageByName("/usr/lib/system/libdyld.dylib");
    void* libdyldHandle = dlopen("/usr/lib/system/libdyld.dylib", RTLD_NOW);

    void* dlopen_global_var_ptr = MSFindSymbol(libdyldImage, "__ZN5dyld45gDyldE");

    MSHookFunction(dlopen, replaced_dlopen, (void **) &original_dlopen);

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_14_1 && !dlopen_global_var_ptr) {
        void* dlopen_internal_ptr = MSFindSymbol(libdyldImage, "__ZL15dlopen_internalPKciPv");

        if(dlopen_internal_ptr) {
            MSHookFunction(dlopen_internal_ptr, replaced_dlopen_internal, (void **) &original_dlopen_internal);
        }
    } else {
        void* dlopen_from_ptr = dlsym(libdyldHandle, "dlopen_from");

        if(dlopen_from_ptr) {
            MSHookFunction(dlopen_from_ptr, replaced_dlopen_internal, (void **) &original_dlopen_internal);
        }
    }

    // MSCloseImage(libdyldImage);
}

void shadowhook_dyld_symlookup(HKSubstitutor* hooks) {
    MSHookFunction(dlsym, replaced_dlsym, (void **) &original_dlsym);
}

void shadowhook_dyld_symaddrlookup(HKSubstitutor* hooks) {
    MSHookFunction(dladdr, replaced_dladdr, (void **) &original_dladdr);
}
