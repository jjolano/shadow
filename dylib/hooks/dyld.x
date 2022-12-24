#import "hooks.h"

uint32_t _shdw_dyld_image_count = 0;
NSArray* _shdw_dyld_collection = nil;
NSArray* _shdw_dyld_add_image = nil;
NSArray* _shdw_dyld_remove_image = nil;
// NSMutableData* _shdw_dyld_task_dyld_info = nil;

static uint32_t (*original_dyld_image_count)(void);
static uint32_t replaced_dyld_image_count(void) {
    if(_shdw_dyld_collection) {
        return _shdw_dyld_image_count;
    }

    return original_dyld_image_count();
}

static const struct mach_header* (*original_dyld_get_image_header)(uint32_t image_index);
static const struct mach_header* replaced_dyld_get_image_header(uint32_t image_index) {
    if(_shdw_dyld_collection) {
        return image_index < _shdw_dyld_image_count ? (struct mach_header *)[_shdw_dyld_collection[image_index][@"mach_header"] unsignedLongValue] : NULL;
    }

    return original_dyld_get_image_header(image_index);
}

static intptr_t (*original_dyld_get_image_vmaddr_slide)(uint32_t image_index);
static intptr_t replaced_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    if(_shdw_dyld_collection) {
        return image_index < _shdw_dyld_image_count ? (intptr_t)[_shdw_dyld_collection[image_index][@"slide"] unsignedLongValue] : 0;
    }
    
    return original_dyld_get_image_vmaddr_slide(image_index);
}

static const char* (*original_dyld_get_image_name)(uint32_t image_index);
static const char* replaced_dyld_get_image_name(uint32_t image_index) {
    if(_shdw_dyld_collection) {
        return image_index < _shdw_dyld_image_count ? [_shdw_dyld_collection[image_index][@"name"] UTF8String] : NULL;
    }

    const char* result = original_dyld_get_image_name(image_index);

    if([_shadow isCPathRestricted:result] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return "/usr/lib/dyld";
    }

    return result;
}

static void* (*original_dlopen)(const char* path, int mode);
static void* replaced_dlopen(const char* path, int mode) {
    void* handle = original_dlopen(path, mode);

    if([_shadow isAddrRestricted:handle] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return NULL;
    }

    return handle;
}

static bool (*original_dlopen_preflight)(const char* path);
static bool replaced_dlopen_preflight(const char* path) {
    bool result = original_dlopen_preflight(path);

    if(result) {
        if([_shadow isCPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return false;
        }
    }

    return result;
}

static void (*original_dyld_register_func_for_add_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return original_dyld_register_func_for_add_image(func);
    }

    if(!func) {
        // Don't do anything if function doesn't exist
        return;
    }

    // add to our collection
    NSMutableArray* _dyld_add_image = _shdw_dyld_add_image ? [_shdw_dyld_add_image mutableCopy] : [NSMutableArray new];
    [_dyld_add_image addObject:@((unsigned long)func)];
    _shdw_dyld_add_image = [_dyld_add_image copy];

    // do initial call
    if(_shdw_dyld_collection) {
        for(NSDictionary* dylib in _shdw_dyld_collection) {
            func((struct mach_header *)[dylib[@"mach_header"] unsignedLongValue], (intptr_t)[dylib[@"slide"] unsignedLongValue]);
        }
    }
}

static void (*original_dyld_register_func_for_remove_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_remove_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return original_dyld_register_func_for_remove_image(func);
    }

    if(!func) {
        // Don't do anything if function doesn't exist
        return;
    }

    // add to our collection
    NSMutableArray* _dyld_remove_image = _shdw_dyld_remove_image ? [_shdw_dyld_remove_image mutableCopy] : [NSMutableArray new];
    [_dyld_remove_image addObject:@((unsigned long)func)];
    _shdw_dyld_remove_image = [_dyld_remove_image copy];
}

static kern_return_t (*original_task_info)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt);
static kern_return_t replaced_task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    kern_return_t result = original_task_info(target_task, flavor, task_info_out, task_info_outCnt);

    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return result;
    }

    if(flavor == TASK_DYLD_INFO) {
        if(result == KERN_SUCCESS) {
            NSLog(@"%@: %@", @"task_info", @"TASK_DYLD_INFO");

            struct task_dyld_info *task_info = (struct task_dyld_info *) task_info_out;
            struct dyld_all_image_infos *dyld_info = (struct dyld_all_image_infos *) task_info->all_image_info_addr;
            dyld_info->infoArrayCount = 1;

            // todo: rebuild/filter this array
            // NSMutableData* data = _shdw_dyld_task_dyld_info ? _shdw_dyld_task_dyld_info : [NSMutableData data];
            // struct dyld_image_info* infoArray = [[NSMutableData dataWithBytes:dyld_info->infoArray length:(sizeof(struct dyld_image_info) * dyld_info->infoArrayCount)] mutableBytes];
            // struct dyld_image_info* infoArrayEnd = infoArray + (sizeof(struct dyld_image_info) * dyld_info->infoArrayCount);

            // while(infoArray < infoArrayEnd) {
            //     if(![_shadow isCPathRestricted:infoArray->imageFilePath]) {
            //         // add to our filtered array
            //         NSLog(@"%@: %@: %s", @"task_info", @"adding", infoArray->imageFilePath);

            //         NSMutableData* info_safe = [NSMutableData dataWithBytes:infoArray length:sizeof(struct dyld_image_info)];
            //         [data appendData:info_safe];
            //     }

            //     infoArray++;
            // }

            // _shdw_dyld_task_dyld_info = data;
            // dyld_info->infoArray = [_shdw_dyld_task_dyld_info bytes];
            // dyld_info->infoArrayCount = [_shdw_dyld_task_dyld_info length] / sizeof(struct dyld_image_info);
        }

        return result;
    }

    return result;
}

void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide) {
    // Check if we already have this lib.
    // If not, add it
    if(_shdw_dyld_collection) {
        for(NSDictionary* dylib in _shdw_dyld_collection) {
            if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                // Already exists - skip function.
                return;
            }
        }
    }

    const char* image_path = dyld_image_path_containing_address(mh);
    NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

    // Add if safe dylib.
    if(![image_name hasPrefix:@"/System"] && ![image_name hasPrefix:@"/var/containers"] && ![_shadow isPathRestricted:image_name]) {
        NSMutableArray* _dyld_collection = _shdw_dyld_collection ? [_shdw_dyld_collection mutableCopy] : [NSMutableArray new];

        NSDictionary* dylib = @{
            @"name" : image_name,
            @"mach_header" : @((unsigned long) mh),
            @"slide" : @((unsigned long) vmaddr_slide)
        };

        NSLog(@"%@: %@: %@", @"dyld", @"adding lib", dylib[@"name"]);

        [_dyld_collection addObject:dylib];
        _shdw_dyld_collection = [_dyld_collection copy];
        _shdw_dyld_image_count = [_dyld_collection count];
    }
}

void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_collection) {
        // Check if we already have this lib.
        // If not, do nothing
        NSDictionary* dylibToRemove = nil;

        for(NSDictionary* dylib in _shdw_dyld_collection) {
            if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                // Remove this from our collection
                NSLog(@"%@: %@: %@", @"dyld", @"removing lib", dylib[@"name"]);

                // Don't remove while in enumeration, store for later
                dylibToRemove = dylib;
                break;
            }
        }

        if(dylibToRemove) {
            NSMutableArray* _dyld_collection = [_shdw_dyld_collection mutableCopy];
            [_dyld_collection removeObject:dylibToRemove];
            _shdw_dyld_collection = [_dyld_collection copy];
            _shdw_dyld_image_count = [_dyld_collection count];
        }
    }
}

void shadowhook_dyld_shdw_add_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_add_image && _shdw_dyld_collection) {
        NSDictionary* dylibFound = nil;

        for(NSDictionary* dylib in _shdw_dyld_collection) {
            if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                dylibFound = dylib;
                break;
            }
        }

        if(!dylibFound) {
            return;
        }

        // Call event handlers.
        NSLog(@"%@: %@", @"dyld", @"add_image calling handlers");

        for(NSNumber* func_ptr in _shdw_dyld_add_image) {
            void (*func)(const struct mach_header*, intptr_t) = (void *)[func_ptr unsignedLongValue];
            func(mh, vmaddr_slide);
        }
    }
}

void shadowhook_dyld_shdw_remove_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_remove_image && _shdw_dyld_collection) {
        NSDictionary* dylibFound = nil;

        for(NSDictionary* dylib in _shdw_dyld_collection) {
            if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                dylibFound = dylib;
                break;
            }
        }

        if(!dylibFound) {
            return;
        }

        // Call event handlers.
        NSLog(@"%@: %@", @"dyld", @"remove_image calling handlers");

        for(NSNumber* func_ptr in _shdw_dyld_remove_image) {
            void (*func)(const struct mach_header*, intptr_t) = (void *)[func_ptr unsignedLongValue];
            func(mh, vmaddr_slide);
        }
    }
}

static void* (*original_dlsym)(void* handle, const char* symbol);
static void* replaced_dlsym(void* handle, const char* symbol) {
    void* addr = original_dlsym(handle, symbol);

    if(addr) {
        // Check origin of resolved symbol
        if([_shadow isAddrRestricted:addr] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            if(symbol) {
                NSLog(@"%@: %@: %s", @"dlsym", @"restricted symbol lookup", symbol);
            }

            return NULL;
        }
    }

    return addr;
}

static int (*original_dladdr)(const void* addr, Dl_info* info);
static int replaced_dladdr(const void* addr, Dl_info* info) {
    int result = original_dladdr(addr, info);
    
    if(result) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strlen(info->dli_fname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            if(info->dli_sname) {
                NSLog(@"%@: %@: %@ -> %s", @"dyld", @"dladdr", path, info->dli_sname);

                void* orig_addr = original_dlsym(RTLD_NEXT, info->dli_sname);

                if(orig_addr) {
                    // Return the original lookup if possible
                    result = replaced_dladdr(orig_addr, info);
                } else {
                    dlerror();
                }
            }
        }
    } else {
        memset(info, 0, sizeof(Dl_info));
    }

    return result;
}

void shadowhook_dyld(void) {
    MSHookFunction(_dyld_get_image_name, replaced_dyld_get_image_name, (void **) &original_dyld_get_image_name);
    MSHookFunction(_dyld_image_count, replaced_dyld_image_count, (void **) &original_dyld_image_count);
    MSHookFunction(_dyld_get_image_header, replaced_dyld_get_image_header, (void **) &original_dyld_get_image_header);
    MSHookFunction(_dyld_get_image_vmaddr_slide, replaced_dyld_get_image_vmaddr_slide, (void **) &original_dyld_get_image_vmaddr_slide);
    MSHookFunction(_dyld_register_func_for_add_image, replaced_dyld_register_func_for_add_image, (void **) &original_dyld_register_func_for_add_image);
    MSHookFunction(_dyld_register_func_for_remove_image, replaced_dyld_register_func_for_remove_image, (void **) &original_dyld_register_func_for_remove_image);
}

void shadowhook_dyld_extra(void) {
    MSHookFunction(task_info, replaced_task_info, (void **) &original_task_info);
    MSHookFunction(dlopen, replaced_dlopen, (void **) &original_dlopen);
    MSHookFunction(dlopen_preflight, replaced_dlopen_preflight, (void **) &original_dlopen_preflight);
}

void shadowhook_dyld_symlookup(void) {
    MSHookFunction(dlsym, replaced_dlsym, (void **) &original_dlsym);
    MSHookFunction(dladdr, replaced_dladdr, (void **) &original_dladdr);
}
