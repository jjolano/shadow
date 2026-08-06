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
// we patch its arrays directly and skip the task_info hook. When NULL (very
// old iOS), the task_info hack below stays active.
static struct dyld_all_image_infos* _shdw_all_image_infos = NULL;

// Filtered mirrors of dyld's image info / uuid arrays: single fixed-capacity
// vm_allocate'd buffers (never reallocated or freed, so the pointers we
// publish into dyld_all_image_infos stay valid forever), rebuilt in place
// under the lock whenever the collection changes. Path strings are retained
// in `_shdw_dyld_path_pool` for the lifetime of the process so
// fileSystemRepresentation pointers never dangle after a collection removal.
// In-place rebuilds can tear for an external walker mid-walk (µs window) —
// harmless: it only ever misreads a path, and a detection suite misreading
// paths is exactly the direction we want.
#define SHADOW_DYLD_MIRROR_CAPACITY 4096   // beyond any real process's image count

static os_unfair_lock _shdw_dyld_mirror_lock = OS_UNFAIR_LOCK_INIT;
static struct dyld_image_info* _shdw_dyld_info_array = NULL;
static struct dyld_uuid_info* _shdw_dyld_uuid_array = NULL;
static NSMutableArray* _shdw_dyld_path_pool = nil;

// dyld's original uuid array, captured before our first patch overwrites the
// struct's uuidArray pointer (later rebuilds must scan the original, not our
// own filtered mirror, or new image uuids would never appear).
static const struct dyld_uuid_info* _shdw_real_uuid_array = NULL;
static uintptr_t _shdw_real_uuid_count = 0;

// Feature flag: "MemoryLevelHiding" in Shadow's prefs plist (default OFF).
// SHADOW_PREFS_PLIST tracks the bundle id (me.jjolano.shadow); on rootless the
// plist lives under /var/jb, so try both paths. A missing/unreadable plist
// simply means the flag is off — memory hiding must never break the hook.
static BOOL shdw_dyld_memory_hiding_enabled(void) {
    // Escalation: when a detection library is present, memory hiding forces
    // on regardless of the prefs flag (set by dylib.x before hooks install).
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
                enabled = [prefs[@"MemoryLevelHiding"] boolValue];
                break;
            }
        }
    });

    return enabled;
}

static void shadowhook_dyld_rebuild_dyldinfo(void);

// todo: maybe hook this private symbol
// extern void call_funcs_for_add_image(struct mach_header *mh, unsigned long vmaddr_slide);

static uint32_t (*original_dyld_image_count)();
static uint32_t replaced_dyld_image_count() {
    if(isCallerTweak()) {
        return original_dyld_image_count();
    }

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    return [_dyld_collection count];
}

static const struct mach_header* (*original_dyld_get_image_header)(uint32_t image_index);
static const struct mach_header* replaced_dyld_get_image_header(uint32_t image_index) {
    if(isCallerTweak()) {
        return original_dyld_get_image_header(image_index);
    }

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    return image_index < [_dyld_collection count] ? (struct mach_header *)[_dyld_collection[image_index][@"mach_header"] pointerValue] : NULL;
}

static intptr_t (*original_dyld_get_image_vmaddr_slide)(uint32_t image_index);
static intptr_t replaced_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    if(isCallerTweak()) {
        return original_dyld_get_image_vmaddr_slide(image_index);
    }

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    return image_index < [_dyld_collection count] ? (intptr_t)[_dyld_collection[image_index][@"slide"] pointerValue] : 0;
}

static const char* (*original_dyld_get_image_name)(uint32_t image_index);
static const char* replaced_dyld_get_image_name(uint32_t image_index) {
    if(isCallerTweak()) {
        return original_dyld_get_image_name(image_index);
    }

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    return image_index < [_dyld_collection count] ? [_dyld_collection[image_index][@"name"] fileSystemRepresentation] : NULL;
}

// _dyld_image_path_containing_address is called directly by commercial
// detection SDKs (bypasses dyld API filtering) AND by Shadow's own Core.m
// (isAddrExternal/isAddrRestricted → isCallerTweak). Return truth to the
// tweak's own callers, lie (executable path) to everyone else.
// The reentrancy flag is _Thread_local because the only recursion here is
// same-thread (isCallerTweak → isAddrExternal → this hook, guarded by the
// flag) — per-thread scope is exactly right and needs no lock.
static _Thread_local BOOL _shdw_dyipca_in_hook = NO;

static const char* (*original_dyld_image_path_containing_address)(const void* addr);
static const char* replaced_dyld_image_path_containing_address(const void* addr) {
    if(_shdw_dyipca_in_hook || !addr) {
        return original_dyld_image_path_containing_address(addr);
    }

    _shdw_dyipca_in_hook = YES;

    // Is the CALLER of this hook inside the tweak? (not the addr arg)
    BOOL caller_is_tweak = [_shadow isAddrExternal:__builtin_return_address(0)];

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
    BOOL caller_outside_app = [_shadow isAddrExternal:__builtin_return_address(0)];

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

static kern_return_t (*original_task_info)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt);
static kern_return_t replaced_task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    if(isCallerTweak()) {
        return original_task_info(target_task, flavor, task_info_out, task_info_outCnt);
    }

    kern_return_t result = original_task_info(target_task, flavor, task_info_out, task_info_outCnt);

    if(flavor == TASK_DYLD_INFO && result == KERN_SUCCESS) {
        struct task_dyld_info *task_info = (struct task_dyld_info *) task_info_out;
        struct dyld_all_image_infos *dyld_info = (struct dyld_all_image_infos *) task_info->all_image_info_addr;
        dyld_info->infoArrayCount = 1;
        dyld_info->uuidArrayCount = 1;

        // todo: improve this
    }

    return result;
}

void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!mh) {
        return;
    }

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
            void* sym;

            // try to find the real original addr
            do {
                sym = dlsym(RTLD_NEXT, info->dli_sname);
            } while(sym && [_shadow isAddrRestricted:sym]);
            
            if(sym) {
                return original_dladdr(sym, info);
            } else {
                // as a fallback, we'll just say this addr is part of the executable itself
                info->dli_fname = [[Shadow getExecutablePath] fileSystemRepresentation];
            }
        }
    }

    return result;
}

static void shadowhook_dyld_rebuild_dyldinfo(void) {
    // Degraded mode: no struct to patch, keep the task_info hack.
    if(!_shdw_all_image_infos) {
        return;
    }

    // Feature-flagged (default OFF): leave dyld's real data alone entirely.
    if(!shdw_dyld_memory_hiding_enabled()) {
        return;
    }

    os_unfair_lock_lock(&_shdw_dyld_mirror_lock);

    // Allocate the fixed-capacity mirrors once (lazily). vm_allocate'd, never
    // reallocated: the published pointers can't dangle.
    static BOOL mirrorAllocFailed = NO;

    if(!mirrorAllocFailed) {
        if(!_shdw_dyld_info_array
        && vm_allocate(mach_task_self(), (vm_address_t *) &_shdw_dyld_info_array, SHADOW_DYLD_MIRROR_CAPACITY * sizeof(struct dyld_image_info), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
            mirrorAllocFailed = YES;
            NSLog(@"shadow: dyld: failed to allocate info mirror, memory hiding disabled (fail soft)");
        }

        if(!_shdw_dyld_uuid_array
        && vm_allocate(mach_task_self(), (vm_address_t *) &_shdw_dyld_uuid_array, SHADOW_DYLD_MIRROR_CAPACITY * sizeof(struct dyld_uuid_info), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
            mirrorAllocFailed = YES;
            NSLog(@"shadow: dyld: failed to allocate uuid mirror, memory hiding disabled (fail soft)");
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
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        NSUInteger count = MIN([_dyld_collection count], SHADOW_DYLD_MIRROR_CAPACITY);

        // Filtered dyld_image_info array, one entry per collection entry.
        for(NSUInteger i = 0; i < count; i++) {
            NSDictionary* dylib = _dyld_collection[i];

            _shdw_dyld_info_array[i].imageLoadAddress = (struct mach_header *)[dylib[@"mach_header"] pointerValue];
            _shdw_dyld_info_array[i].imageFilePath = [dylib[@"name"] fileSystemRepresentation];

            // ponytail: imageFileModDate is unused by detection suites; they only walk names/counts
            _shdw_dyld_info_array[i].imageFileModDate = 0;
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
                        _shdw_dyld_uuid_array[uuidCount].imageLoadAddress = mh;
                        memcpy(_shdw_dyld_uuid_array[uuidCount].imageUUID, _shdw_real_uuid_array[j].imageUUID, sizeof(uuid_t));
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
            _shdw_all_image_infos->infoArray = _shdw_dyld_info_array;
            _shdw_all_image_infos->infoArrayCount = (uint32_t) count;
            _shdw_all_image_infos->uuidArray = uuidCount ? _shdw_dyld_uuid_array : _shdw_all_image_infos->uuidArray;
            _shdw_all_image_infos->uuidArrayCount = (uint32_t) uuidCount;

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

    MSHookFunction(_dyld_get_image_name, replaced_dyld_get_image_name, (void **) &original_dyld_get_image_name);
    MSHookFunction(_dyld_image_count, replaced_dyld_image_count, (void **) &original_dyld_image_count);
    MSHookFunction(_dyld_get_image_header, replaced_dyld_get_image_header, (void **) &original_dyld_get_image_header);
    MSHookFunction(_dyld_get_image_vmaddr_slide, replaced_dyld_get_image_vmaddr_slide, (void **) &original_dyld_get_image_vmaddr_slide);
    MSHookFunction(_dyld_register_func_for_add_image, replaced_dyld_register_func_for_add_image, (void **) &original_dyld_register_func_for_add_image);
    MSHookFunction(_dyld_register_func_for_remove_image, replaced_dyld_register_func_for_remove_image, (void **) &original_dyld_register_func_for_remove_image);

    // Resolve the exported dyld_all_image_infos global so we can patch its
    // arrays directly. task_info returns the SAME struct address, so once
    // patching is active the task_info hook is redundant.
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
        // Very old iOS: degrade to the task_info hack (lie about counts).
        NSLog(@"[Shadow] dyld_all_image_infos not found, falling back to task_info hack");
        MSHookFunction(task_info, replaced_task_info, (void **) &original_task_info);
    }

    // Directly linkable — declared in vendor/apple/dyld_priv.h (Core.m calls
    // it the same way); no MSFindSymbol needed.
    MSHookFunction(dyld_image_path_containing_address, replaced_dyld_image_path_containing_address, (void **) &original_dyld_image_path_containing_address);
    MSHookFunction(dyld_image_header_containing_address, replaced_dyld_image_header_containing_address, (void **) &original_dyld_image_header_containing_address);

    MSHookFunction(dlopen_preflight, replaced_dlopen_preflight, (void **) &original_dlopen_preflight);

    MSHookFunction(dlerror, replaced_dlerror, (void **) &original_dlerror);
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
