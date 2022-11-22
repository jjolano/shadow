#import "hooks.h"

NSMutableArray* _shdw_dyld_collection = nil;
NSMutableArray* _shdw_dyld_add_image = nil;
NSMutableArray* _shdw_dyld_remove_image = nil;

%group shadowhook_dyld
// %hookf(int32_t, NSVersionOfLinkTimeLibrary, const char* libraryName) {
//     HBLogDebug(@"%@: %@: %s", @"dyld", @"NSVersionOfRunTimeLibrary", libraryName);
//     return %orig;
// }

// %hookf(int32_t, NSVersionOfRunTimeLibrary, const char* libraryName) {
//     HBLogDebug(@"%@: %@: %s", @"dyld", @"NSVersionOfRunTimeLibrary", libraryName);
//     return %orig;
// }

%hookf(uint32_t, _dyld_image_count) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return [_dyld_collection count];
    }

    return %orig;
}

%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return image_index < [_dyld_collection count] ? (struct mach_header *)[_dyld_collection[image_index][@"mach_header"] unsignedLongValue] : NULL;
    }

    return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return image_index < [_dyld_collection count] ? (intptr_t)[_dyld_collection[image_index][@"slide"] unsignedLongValue] : 0;
    }
    
    return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    if(_shdw_dyld_collection) {
        NSArray* _dyld_collection = [_shdw_dyld_collection copy];
        return image_index < [_dyld_collection count] ? [_dyld_collection[image_index][@"name"] fileSystemRepresentation] : NULL;
    }

    const char* result = %orig;

    if(result) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:result length:strlen(result)];

        HBLogDebug(@"%@: %@: %@", @"dyld", @"_dyld_get_image_name", image_name);

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return "/usr/lib/system/libsystem_c.dylib";
        }
    }

    return result;
}

%hookf(void *, dlopen, const char *path, int mode) {
    void* handle = nil;

    if(path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if(![image_name containsString:@"/"]) {
            handle = %orig;
            const char* image_path = dyld_image_path_containing_address(handle);

            if(image_path) {
                image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];
            }
        }

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            if(handle) {
                dlclose(handle);
            }

            return NULL;
        }
    }

    return handle ? handle : %orig;
}

%hookf(bool, dlopen_preflight, const char *path) {
    if(path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([image_name containsString:@"/"]) {
            if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                return false;
            }
        } else {
            if(!dlopen(path, RTLD_NOLOAD)) {
                return false;
            }
        }
    }

    return %orig;
}

%hookf(int, dladdr, const void *addr, Dl_info *info) {
    int result = %orig;

    if(result && info) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strlen(info->dli_fname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            if(info->dli_sname) {
                NSString* sym = @(info->dli_sname);

                HBLogDebug(@"%@: %@: %@ -> %@", @"dyld", @"dladdr", path, sym);

                if([sym hasPrefix:@"_logos_method"]) {
                    // return the lookup for the original method
                    return %orig(dlsym(RTLD_DEFAULT, [[sym stringByReplacingOccurrencesOfString:@"_logos_method" withString:@"_logos_orig"] UTF8String]), info);
                }

                if([sym isEqualToString:@"__dso_handle"]) {
                    return %orig(dlsym(RTLD_DEFAULT, "__dso_handle"), info);
                }

                void* orig_addr = dlsym(RTLD_DEFAULT, [[@"original_" stringByAppendingString:sym] UTF8String]);

                if(orig_addr) {
                    return %orig(orig_addr, info);
                }
            }

            memset(info, 0, sizeof(Dl_info));
            return 0;
        }
    }

    return result;
}
%end

%group shadowhook_dyld_dlsym
%hookf(void *, dlsym, void *handle, const char *symbol) {
    void* addr = %orig;

    if(addr) {
        // Check origin of resolved symbol
        const char* image_path = dyld_image_path_containing_address(addr);

        if([_shadow isCPathRestricted:image_path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            HBLogDebug(@"%@: %@: %@ -> %s", @"dlsym", @"restricted symbol lookup", @(symbol), image_path);
            return NULL;
        }
    }

    return addr;
}
%end

%group shadowhook_dyld_extra
%hookf(void, _dyld_register_func_for_add_image, void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    // Check who's interested in this...
    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return %orig;
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

%hookf(void, _dyld_register_func_for_remove_image, void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    // Check who's interested in this...
    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return %orig;
    }

    // add to our collection
    if(!_shdw_dyld_remove_image) {
        _shdw_dyld_remove_image = [NSMutableArray new];
    }

    [_shdw_dyld_remove_image addObject:@((unsigned long)func)];
}

// %hookf(bool, dyld_process_is_restricted) {
//     return true;
// }

// %hookf(bool, dyld_shared_cache_some_image_overridden) {
//     return false;
// }

// %hookf(bool, dyld_has_inserted_or_interposing_libraries) {
//     return false;
// }

%hookf(kern_return_t, task_info, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt) {
    if([_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        return %orig;
    }

    if(flavor == TASK_DYLD_INFO) {
        kern_return_t result = %orig;

        if(result == KERN_SUCCESS) {
            HBLogDebug(@"%@: %@", @"task_info", @"TASK_DYLD_INFO");

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
            //         HBLogDebug(@"%@: %@: %s", @"task_info", @"adding", infoArray->imageFilePath);

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

    return %orig;
}
%end

void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(!_shdw_dyld_collection) {
        _shdw_dyld_collection = [NSMutableArray new];

        // uint32_t count = _dyld_image_count();

        // for(uint32_t i = 0; i < count; i++) {
        //     const char* _name = _dyld_get_image_name(i);
        //     const struct mach_header* _mh = _dyld_get_image_header(i);
        //     intptr_t _slide = _dyld_get_image_vmaddr_slide(i);

        //     NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:_name length:strlen(_name)];

        //     if([_shadow isPathRestricted:image_name]) {
        //         // Got a filtered dylib.
        //         continue;
        //     }

        //     // Safe dylib. Add to our collection
        //     NSDictionary* dylib = @{
        //         @"name" : image_name,
        //         @"mach_header" : @((unsigned long) _mh),
        //         @"slide" : @((unsigned long) _slide)
        //     };

        //     HBLogDebug(@"%@: %@: %@", @"dyld", @"adding lib (init)", image_name);

        //     [_shdw_dyld_collection addObject:dylib];
        // }

        // _shdw_dyld_image_count = [_shdw_dyld_collection count];
    }

    // Check if we already have this lib.
    // If not, add it
    for(NSDictionary* dylib in _shdw_dyld_collection) {
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

        HBLogDebug(@"%@: %@: %@", @"dyld", @"adding lib", dylib[@"name"]);

        [_shdw_dyld_collection addObject:dylib];
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
                HBLogDebug(@"%@: %@: %@", @"dyld", @"removing lib", dylib[@"name"]);

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
        HBLogDebug(@"%@: %@", @"dyld", @"add_image calling handlers");

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
        HBLogDebug(@"%@: %@", @"dyld", @"remove_image calling handlers");

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

void shadowhook_dyld(void) {
    %init(shadowhook_dyld);
}

void shadowhook_dyld_extra(void) {
    %init(shadowhook_dyld_extra);
}

void shadowhook_dyld_symlookup(void) {
    %init(shadowhook_dyld_dlsym);
}
