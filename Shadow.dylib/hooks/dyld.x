#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wframe-address"

#import "hooks.h"

static NSMutableArray<NSDictionary *>* _shdw_dyld_collection = nil;
static NSMutableArray<NSValue *>* _shdw_dyld_add_image = nil;
static NSMutableArray<NSValue *>* _shdw_dyld_remove_image = nil;
static BOOL _shdw_dyld_error = NO;
// static NSOperationQueue* _shdw_dyld_queue = nil;
// NSMutableData* _shdw_dyld_task_dyld_info = nil;

// todo: maybe hook this private symbol
// extern void call_funcs_for_add_image(struct mach_header *mh, unsigned long vmaddr_slide);
#include <os/log.h>
#undef isCallerTweak
bool isCallerTweak() {
    // NSLog(@"%@", NSThread.callStackSymbols);
    // os_log(OS_LOG_DEFAULT, "%{public}@", NSThread.callStackSymbols);
    // return true;
    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    void *retaddrs[] = {
        __builtin_return_address(0),
        __builtin_return_address(1),
        __builtin_return_address(2),
        __builtin_return_address(3),
        __builtin_return_address(4),
        __builtin_return_address(5),
        __builtin_return_address(6),
        __builtin_return_address(7),
    };
    for (int i = 0; i < 8; i++) {
        void *addr = __builtin_extract_return_addr(retaddrs[i]);
        if (![_shadow isAddrExternal:addr]) { // address is belong to app
            return false;
        }

        const char* image_path = dyld_image_path_containing_address(addr);

        for (NSDictionary *img in _dyld_collection) {
            if (!strcmp([img[@"name"] UTF8String], image_path)) {
                return false; // is in safe module list
            }
        }
        // if (![_shadow isAddrRestricted:addr]) { // address is belong to tweak
        //     return true;
        // }
    }
    return true;
    // for (NSString *sym in NSThread.callStackSymbols) {
    //     // do something with object
    //     if ([sym containsString:@"libinjector.dylib"]) { // RootHide's injector
    //         return true;
    //     }
    //     if ([sym containsString:@"tweaks_iterate"] || [sym containsString:@"injection_init"]) { // RootHide's injector
    //         return true;
    //     }
    // }
    // return false;
}

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
    // NSLog(@"_dyld_get_image_name from %p (%d): %@", __builtin_extract_return_addr(__builtin_return_address(0)), isCallerTweak(), NSThread.callStackSymbols);
    if(isCallerTweak()) {
        return original_dyld_get_image_name(image_index);
    }

    NSArray* _dyld_collection = [_shdw_dyld_collection copy];
    const char *ret = image_index < [_dyld_collection count] ? [_dyld_collection[image_index][@"name"] UTF8String] : NULL;
    // NSLog(@"_dyld_get_image_name -> %s", ret ? ret: "");
    return ret;
}

static void* (*original_dlopen)(const char* path, int mode);
static void* replaced_dlopen(const char* path, int mode) {
    if(isCallerTweak() || !path) {
        return original_dlopen(path, mode);
    }

    if(path[0] != '/') {
        if(![_shadow isPathRestricted:@(path) options:@{
            kShadowRestrictionWorkingDir : @"/usr/lib",
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
            kShadowRestrictionWorkingDir : @"/usr/lib",
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
            kShadowRestrictionWorkingDir : @"/usr/lib",
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

        NSLog(@"%@: %@: %@", @"dyld", @"checking lib", path);
        if([path hasPrefix:@"/System"] || ![_shadow isPathRestricted:path options:@{kShadowRestrictionEnableResolve : @(NO)}]) {
            NSLog(@"%@: %@: %@", @"dyld", @"adding lib", path);

            [_shdw_dyld_collection addObject:@{
                @"name" : path,
                @"mach_header" : [NSValue valueWithPointer:mh],
                @"slide" : [NSValue valueWithPointer:(void *)vmaddr_slide]
            }];

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

void shadowhook_dyld(HKSubstitutor* hooks) {
    _shdw_dyld_collection = [NSMutableArray new];
    _shdw_dyld_add_image = [NSMutableArray new];
    _shdw_dyld_remove_image = [NSMutableArray new];

    _dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
    _dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);

    MSHookFunction(_dyld_get_image_name, replaced_dyld_get_image_name, (void **) &original_dyld_get_image_name);

    // !! err in ellekit's substrate, because _dyld_image_count uses x16, conflicts with ellekit
    MSHookFunction(_dyld_image_count, replaced_dyld_image_count, (void **) &original_dyld_image_count);
    
    MSHookFunction(_dyld_get_image_header, replaced_dyld_get_image_header, (void **) &original_dyld_get_image_header);
    MSHookFunction(_dyld_get_image_vmaddr_slide, replaced_dyld_get_image_vmaddr_slide, (void **) &original_dyld_get_image_vmaddr_slide);
    MSHookFunction(_dyld_register_func_for_add_image, replaced_dyld_register_func_for_add_image, (void **) &original_dyld_register_func_for_add_image);
    MSHookFunction(_dyld_register_func_for_remove_image, replaced_dyld_register_func_for_remove_image, (void **) &original_dyld_register_func_for_remove_image);

    MSHookFunction(task_info, replaced_task_info, (void **) &original_task_info);
    
    // !! will cause err in Dobby if directly hook using import address, must use findSymbol
    void *p_dlopen_preflight = MSFindSymbol(MSGetImageByName("/usr/lib/system/libdyld.dylib"), "_dlopen_preflight");
    MSHookFunction(p_dlopen_preflight, replaced_dlopen_preflight, (void **) &original_dlopen_preflight);

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
