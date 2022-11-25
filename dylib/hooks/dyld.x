#import "hooks.h"

NSMutableArray* _shdw_dyld_collection = nil;
NSMutableArray* _shdw_dyld_add_image = nil;
NSMutableArray* _shdw_dyld_remove_image = nil;

static uint32_t (*original_dyld_image_count)(void);
static uint32_t replaced_dyld_image_count(void) {
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
        return image_index < [_dyld_collection count] ? (struct mach_header *)[_dyld_collection[image_index][@"mach_header"] unsignedLongValue] : NULL;
    }

    return original_dyld_get_image_header(image_index);
}

static intptr_t (*original_dyld_get_image_vmaddr_slide)(uint32_t image_index);
static intptr_t replaced_dyld_get_image_vmaddr_slide(uint32_t image_index) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return image_index < [_dyld_collection count] ? (intptr_t)[_dyld_collection[image_index][@"slide"] unsignedLongValue] : 0;
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

    if(result) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:result length:strlen(result)];

        NSLog(@"%@: %@: %@", @"dyld", @"_dyld_get_image_name", image_name);

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return "/usr/lib/system/libsystem_c.dylib";
        }
    }

    return result;
}

static void* (*original_dlopen)(const char* path, int mode);
static void* replaced_dlopen(const char* path, int mode) {
    void* handle = nil;

    if(path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if(![image_name containsString:@"/"]) {
            handle = original_dlopen(path, RTLD_NOLOAD);

            if(handle) {
                const char* image_path = dyld_image_path_containing_address(handle);

                if(image_path) {
                    image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];
                }
            }
        }

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return NULL;
        }
    }

    return handle ? handle : original_dlopen(path, mode);
}

static bool (*original_dlopen_preflight)(const char* path);
static bool replaced_dlopen_preflight(const char* path) {
    if(path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if(![image_name containsString:@"/"]) {
            void* handle = original_dlopen(path, RTLD_NOLOAD);

            if(handle) {
                const char* image_path = dyld_image_path_containing_address(handle);

                if(image_path) {
                    image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];
                }
            }
        }

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return false;
        }
    }

    return original_dlopen_preflight(path);
}

static void (*original_dyld_register_func_for_add_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_add_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if(!func || !dyld_image_path_containing_address(func)) {
        // Don't do anything if function doesn't exist
        return;
    }

    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return original_dyld_register_func_for_add_image(func);
    }

    // add to our collection
    if(!_shdw_dyld_add_image) {
        _shdw_dyld_add_image = [NSMutableArray new];
    }

    [_shdw_dyld_add_image addObject:@((unsigned long)func)];

    // do initial call
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];

        for(NSDictionary* dylib in _dyld_collection) {
            func((struct mach_header *)[dylib[@"mach_header"] unsignedLongValue], (intptr_t)[dylib[@"slide"] unsignedLongValue]);
        }
    }
}

static void (*original_dyld_register_func_for_remove_image)(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide));
static void replaced_dyld_register_func_for_remove_image(void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    if(!func || !dyld_image_path_containing_address(func)) {
        // Don't do anything if function doesn't exist
        return;
    }
    
    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return original_dyld_register_func_for_remove_image(func);
    }

    // add to our collection
    if(!_shdw_dyld_remove_image) {
        _shdw_dyld_remove_image = [NSMutableArray new];
    }

    [_shdw_dyld_remove_image addObject:@((unsigned long)func)];
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
            // NSMutableData* data = [NSMutableData data];
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

            // dyld_info->infoArray = [data bytes];
            // dyld_info->infoArrayCount = [data length] / sizeof(struct dyld_image_info);
        }

        return result;
    }

    return result;
}

void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!_shdw_dyld_collection) {
        _shdw_dyld_collection = [NSMutableArray new];
    }

    // Check if we already have this lib.
    // If not, add it
    NSArray* dyld_collection = [_shdw_dyld_collection copy];

    for(NSDictionary* dylib in dyld_collection) {
        if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
            // Already exists - skip function.
            return;
        }
    }

    const char* image_path = dyld_image_path_containing_address(mh);
    NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

    // Add if safe dylib.
    if(![_shadow isPathRestricted:image_name]) {
        NSDictionary* dylib = @{
            @"name" : image_name,
            @"mach_header" : @((unsigned long) mh),
            @"slide" : @((unsigned long) vmaddr_slide)
        };

        NSLog(@"%@: %@: %@", @"dyld", @"adding lib", dylib[@"name"]);

        [_shdw_dyld_collection addObject:dylib];
    }
}

void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_collection) {
        // Check if we already have this lib.
        // If not, do nothing
        NSDictionary* dylibToRemove = nil;
        NSArray* dyld_collection = [_shdw_dyld_collection copy];

        for(NSDictionary* dylib in dyld_collection) {
            if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                // Remove this from our collection
                NSLog(@"%@: %@: %@", @"dyld", @"removing lib", dylib[@"name"]);

                // Don't remove while in enumeration, store for later
                dylibToRemove = dylib;
                break;
            }
        }

        if(dylibToRemove) {
            [_shdw_dyld_collection removeObject:dylibToRemove];
        }
    }
}

void shadowhook_dyld_shdw_add_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_add_image) {
        NSDictionary* dylibFound = nil;
        NSArray* dyld_collection = [_shdw_dyld_collection copy];

        for(NSDictionary* dylib in dyld_collection) {
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

        NSArray* _dyld_add_image = [_shdw_dyld_add_image copy];

        for(NSNumber* func_ptr in _dyld_add_image) {
            void (*func)(const struct mach_header*, intptr_t) = (void *)[func_ptr unsignedLongValue];

            // Make sure this function still exists...
            const char* image_path = dyld_image_path_containing_address(func);

            if(image_path) {
                func(mh, vmaddr_slide);
            }
        }
    }
}

void shadowhook_dyld_shdw_remove_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_remove_image) {
        NSDictionary* dylibFound = nil;
        NSArray* dyld_collection = [_shdw_dyld_collection copy];

        for(NSDictionary* dylib in dyld_collection) {
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

        NSArray* _dyld_remove_image = [_shdw_dyld_remove_image copy];
        
        for(NSNumber* func_ptr in _dyld_remove_image) {
            void (*func)(const struct mach_header*, intptr_t) = (void *)[func_ptr unsignedLongValue];

            // Make sure this function still exists...
            const char* image_path = dyld_image_path_containing_address(func);

            if(image_path) {
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
        const char* image_path = dyld_image_path_containing_address(addr);

        if([_shadow isCPathRestricted:image_path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            NSLog(@"%@: %@: %@ -> %s", @"dlsym", @"restricted symbol lookup", @(symbol), image_path);
            return NULL;
        }
    }

    return addr;
}

static int (*original_dladdr)(const void* addr, Dl_info* info);
static int replaced_dladdr(const void* addr, Dl_info* info) {
    int result = original_dladdr(addr, info);

    if(result && info) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strlen(info->dli_fname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            if(info->dli_sname) {
                NSString* sym = @(info->dli_sname);

                NSLog(@"%@: %@: %@ -> %@", @"dyld", @"dladdr", path, sym);

                if([sym hasPrefix:@"_logos_method"]) {
                    void* orig_addr = original_dlsym(RTLD_DEFAULT, [[sym stringByReplacingOccurrencesOfString:@"_logos_method" withString:@"_logos_orig"] UTF8String]);

                    if(orig_addr) {
                        return original_dladdr(orig_addr, info);
                    }
                }

                if([sym isEqualToString:@"__dso_handle"]) {
                    return original_dladdr(original_dlsym(RTLD_DEFAULT, "__dso_handle"), info);
                }

                void* orig_addr = original_dlsym(RTLD_SELF, [[@"original_" stringByAppendingString:sym] UTF8String]);

                if(orig_addr) {
                    return original_dladdr(orig_addr, info);
                }
            }

            memset(info, 0, sizeof(Dl_info));
            return 0;
        }
    }

    return result;
}

void shadowhook_dyld(void) {
    MSHookFunction(_dyld_image_count, replaced_dyld_image_count, (void **) &original_dyld_image_count);
    MSHookFunction(_dyld_get_image_header, replaced_dyld_get_image_header, (void **) &original_dyld_get_image_header);
    MSHookFunction(_dyld_get_image_name, replaced_dyld_get_image_name, (void **) &original_dyld_get_image_name);
    MSHookFunction(_dyld_get_image_vmaddr_slide, replaced_dyld_get_image_vmaddr_slide, (void **) &original_dyld_get_image_vmaddr_slide);
    MSHookFunction(dlopen, replaced_dlopen, (void **) &original_dlopen);
    MSHookFunction(dlopen_preflight, replaced_dlopen_preflight, (void **) &original_dlopen_preflight);
}

void shadowhook_dyld_extra(void) {
    MSHookFunction(_dyld_register_func_for_add_image, replaced_dyld_register_func_for_add_image, (void **) &original_dyld_register_func_for_add_image);
    MSHookFunction(_dyld_register_func_for_remove_image, replaced_dyld_register_func_for_remove_image, (void **) &original_dyld_register_func_for_remove_image);
    MSHookFunction(task_info, replaced_task_info, (void **) &original_task_info);
}

void shadowhook_dyld_symlookup(void) {
    MSHookFunction(dlsym, replaced_dlsym, (void **) &original_dlsym);
    MSHookFunction(dladdr, replaced_dladdr, (void **) &original_dladdr);
}
