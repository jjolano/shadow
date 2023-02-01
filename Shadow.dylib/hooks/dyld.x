#import "hooks.h"

NSMutableArray<NSDictionary *>* _shdw_dyld_collection = nil;
NSMutableArray<NSValue *>* _shdw_dyld_add_image = nil;
NSMutableArray<NSValue *>* _shdw_dyld_remove_image = nil;
// NSMutableData* _shdw_dyld_task_dyld_info = nil;

static uint32_t (*original_dyld_image_count)();
static uint32_t replaced_dyld_image_count() {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return [_dyld_collection count];
    }

    return original_dyld_image_count();
}

static const struct mach_header* (*original_dyld_get_image_header)(uint32_t image_index);
static const struct mach_header* replaced_dyld_get_image_header(uint32_t image_index) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return image_index < [_dyld_collection count] ? (struct mach_header *)[_dyld_collection[image_index][@"mach_header"] pointerValue] : NULL;
    }

    return original_dyld_get_image_header(image_index);
}

static intptr_t (*original_dyld_get_image_vmaddr_slide)(uint32_t image_index);
static intptr_t replaced_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return image_index < [_dyld_collection count] ? (intptr_t)[_dyld_collection[image_index][@"slide"] pointerValue] : 0;
    }
    
    return original_dyld_get_image_vmaddr_slide(image_index);
}

static const char* (*original_dyld_get_image_name)(uint32_t image_index);
static const char* replaced_dyld_get_image_name(uint32_t image_index) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return image_index < [_dyld_collection count] ? [_dyld_collection[image_index][@"name"] fileSystemRepresentation] : NULL;
    }

    const char* result = original_dyld_get_image_name(image_index);

    if([_shadow isCPathRestricted:result] && !isCallerTweak()) {
        return "/usr/lib/dyld";
    }

    return result;
}

static void* (*original_dlopen)(const char* path, int mode);
static void* replaced_dlopen(const char* path, int mode) {
    BOOL isTweak = isCallerTweak();

    if([_shadow isCPathRestricted:path] && !isTweak) {
        return NULL;
    }

    void* handle = original_dlopen(path, mode);

    if(handle && (!path || (path && path[0] != '/')) && !isTweak) {
        // todo: handle this case
    }

    return handle;
}

static void* (*original_dlopen_internal)(const char* path, int mode, void* caller);
static void* replaced_dlopen_internal(const char* path, int mode, void* caller) {
    BOOL isTweak = isCallerTweak();

    if([_shadow isCPathRestricted:path] && !isTweak) {
        return NULL;
    }

    void* handle = original_dlopen_internal(path, mode, caller);

    if(handle && (!path || (path && path[0] != '/')) && !isTweak) {
        // todo: handle this case
    }

    return handle;
}

static bool (*original_dlopen_preflight)(const char* path);
static bool replaced_dlopen_preflight(const char* path) {
    if([_shadow isCPathRestricted:path] && !isCallerTweak()) {
        return false;
    }

    return original_dlopen_preflight(path);
}

static void (*original_dyld_register_func_for_add_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if(isCallerTweak()) {
        return original_dyld_register_func_for_add_image(func);
    }

    if(!func) {
        // Don't do anything if function doesn't exist
        return;
    }

    // add to our collection
    if(!_shdw_dyld_add_image) {
        _shdw_dyld_add_image = [NSMutableArray new];
    }

    [_shdw_dyld_add_image addObject:[NSValue valueWithPointer:func]];

    // do initial call
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];

        for(NSDictionary* dylib in _dyld_collection) {
            func((struct mach_header *)[dylib[@"mach_header"] pointerValue], (intptr_t)[dylib[@"slide"] pointerValue]);
        }
    }
}

static void (*original_dyld_register_func_for_remove_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_remove_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if(isCallerTweak()) {
        return original_dyld_register_func_for_remove_image(func);
    }

    if(!func) {
        // Don't do anything if function doesn't exist
        return;
    }

    // add to our collection
    if(!_shdw_dyld_remove_image) {
        _shdw_dyld_remove_image = [NSMutableArray new];
    }

    [_shdw_dyld_remove_image addObject:[NSValue valueWithPointer:func]];
}

static kern_return_t (*original_task_info)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt);
static kern_return_t replaced_task_info(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    kern_return_t result = original_task_info(target_task, flavor, task_info_out, task_info_outCnt);

    if(isCallerTweak()) {
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
    const char* image_path = dyld_image_path_containing_address(mh);

    if(!image_path) {
        return;
    }

    NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strnlen(image_path, PATH_MAX)];

    // Add if safe dylib.
    if([image_name hasPrefix:@"/System"] || [image_name hasPrefix:@"/Developer"] || ![_shadow isPathRestricted:image_name]) {
        if(!_shdw_dyld_collection) {
            _shdw_dyld_collection = [NSMutableArray new];
        }

        NSDictionary* dylib = @{
            @"name" : image_name,
            @"mach_header" : [NSValue valueWithPointer:mh],
            @"slide" : [NSValue valueWithPointer:(void *)vmaddr_slide]
        };

        NSLog(@"%@: %@: %@", @"dyld", @"adding lib", dylib[@"name"]);

        [_shdw_dyld_collection addObject:dylib];

        // Call event handlers.
        NSArray* _dyld_add_image = [_shdw_dyld_add_image copy];
        NSLog(@"%@: %@", @"dyld", @"add_image calling handlers");

        for(NSValue* func_ptr in _dyld_add_image) {
            void (*func)(const struct mach_header*, intptr_t) = [func_ptr pointerValue];
            func(mh, vmaddr_slide);
        }
    }
}

void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_collection) {
        // Check if we already have this lib.
        // If not, do nothing
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
            NSLog(@"%@: %@", @"dyld", @"remove_image calling handlers");

            for(NSValue* func_ptr in _dyld_remove_image) {
                void (*func)(const struct mach_header*, intptr_t) = [func_ptr pointerValue];
                func(mh, vmaddr_slide);
            }
        }
    }
}

static void* (*original_dlsym)(void* handle, const char* symbol);
static void* replaced_dlsym(void* handle, const char* symbol) {
    void* addr = original_dlsym(handle, symbol);

    if(addr) {
        // Check origin of resolved symbol
        if([_shadow isAddrRestricted:addr] && !isCallerTweak()) {
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
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strnlen(info->dli_fname, PATH_MAX)];

        if([_shadow isPathRestricted:path] && !isCallerTweak()) {
            if(info->dli_sname) {
                NSLog(@"%@: %@: %@ -> %s", @"dyld", @"dladdr", path, info->dli_sname);

                void* orig_addr = original_dlsym(RTLD_NEXT, info->dli_sname);

                if(orig_addr) {
                    // Return the original lookup if possible
                    result = original_dladdr(orig_addr, info);
                } else {
                    // if original addr was not found most likly its not a hooked function from us
                    // because we are injected lets not link anything to our selfs
                    memset(info, 0, sizeof(Dl_info));
                    result = 0;
                }
            }
        }
    }

    return result;
}

void shadowhook_dyld(HKSubstitutor* hooks) {
    MSHookFunction(_dyld_get_image_name, replaced_dyld_get_image_name, (void **) &original_dyld_get_image_name);
    MSHookFunction(_dyld_image_count, replaced_dyld_image_count, (void **) &original_dyld_image_count);
    MSHookFunction(_dyld_get_image_header, replaced_dyld_get_image_header, (void **) &original_dyld_get_image_header);
    MSHookFunction(_dyld_get_image_vmaddr_slide, replaced_dyld_get_image_vmaddr_slide, (void **) &original_dyld_get_image_vmaddr_slide);
    MSHookFunction(_dyld_register_func_for_add_image, replaced_dyld_register_func_for_add_image, (void **) &original_dyld_register_func_for_add_image);
    MSHookFunction(_dyld_register_func_for_remove_image, replaced_dyld_register_func_for_remove_image, (void **) &original_dyld_register_func_for_remove_image);

    MSHookFunction(task_info, replaced_task_info, (void **) &original_task_info);
    MSHookFunction(dlopen_preflight, replaced_dlopen_preflight, (void **) &original_dlopen_preflight);
}

void shadowhook_dyld_extra(HKSubstitutor* hooks) {
    // dlopen hook code from Choicy
    MSImageRef libdyldImage = MSGetImageByName("/usr/lib/system/libdyld.dylib");
    void* dlopen_global_var_ptr = MSFindSymbol(libdyldImage, "__ZN5dyld45gDyldE");

    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_14_1 && !dlopen_global_var_ptr) {
        MSHookFunction(dlopen, replaced_dlopen, (void **) &original_dlopen);

        void* dlopen_internal_ptr = MSFindSymbol(libdyldImage, "__ZL15dlopen_internalPKciPv");

        if(dlopen_internal_ptr) {
            MSHookFunction(dlopen_internal_ptr, replaced_dlopen_internal, (void **) &original_dlopen_internal);
        }
    } else {
        void* dlopen_ptr = MSFindSymbol(libdyldImage, "_dlopen");

        if(dlopen_ptr) {
            MSHookFunction(dlopen_ptr, replaced_dlopen, (void **) &original_dlopen);
        } else {
            MSHookFunction(dlopen, replaced_dlopen, (void **) &original_dlopen);
        }

        void* dlopen_from_ptr = MSFindSymbol(libdyldImage, "_dlopen_from");

        if(dlopen_from_ptr) {
            MSHookFunction(dlopen_from_ptr, replaced_dlopen_internal, (void **) &original_dlopen_internal);
        }
    }

    MSCloseImage(libdyldImage);
}

void shadowhook_dyld_symlookup(HKSubstitutor* hooks) {
    MSHookFunction(dlsym, replaced_dlsym, (void **) &original_dlsym);
}

void shadowhook_dyld_symaddrlookup(HKSubstitutor* hooks) {
    MSHookFunction(dladdr, replaced_dladdr, (void **) &original_dladdr);
}
