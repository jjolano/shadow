#import "hooks.h"

BOOL _shdw_dlerror = NO;
uint32_t _shdw_dyld_image_count = 0;
NSArray* _shdw_dyld_collection = nil;
NSArray* _shdw_dyld_add_image = nil;
NSArray* _shdw_dyld_remove_image = nil;

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
    if(_shdw_dyld_image_count > 0) {
        return _shdw_dyld_image_count;
    }

    return %orig;
}

%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    if(_shdw_dyld_image_count > 0) {
        return image_index < _shdw_dyld_image_count ? (struct mach_header *)[_shdw_dyld_collection[image_index][@"mach_header"] unsignedLongValue] : NULL;
    }

    return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    if(_shdw_dyld_image_count > 0) {
        return image_index < _shdw_dyld_image_count ? (intptr_t)[_shdw_dyld_collection[image_index][@"slide"] unsignedLongValue] : 0;
    }
    
    return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    if(_shdw_dyld_image_count > 0) {
        return image_index < _shdw_dyld_image_count ? [_shdw_dyld_collection[image_index][@"name"] UTF8String] : NULL;
    }

    const char* result = %orig(image_index);

    if(result) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:result length:strlen(result)];

        HBLogDebug(@"%@: %@: %@", @"dyld", @"_dyld_get_image_name", image_name);

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return "";
        }
    }

    return result;
}

%hookf(char *, dlerror) {
    char* result = %orig;

    if(result && _shdw_dlerror && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
        _shdw_dlerror = NO;
        return "error";
    }

    return result;
}

%hookf(void *, dlopen, const char *path, int mode) {
    void* handle = %orig;

    if(handle && path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if(![image_name containsString:@"/"]) {
            // todo
        }

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            _shdw_dlerror = YES;
            dlclose(handle);
            return NULL;
        }
    }

    return handle;
}

%hookf(bool, dlopen_preflight, const char *path) {
    bool result = %orig;
    
    if(result && path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([image_name containsString:@"/"]) {
            if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                return false;
            }
        } else {
            // todo
        }
    }

    return result;
}

%hookf(int, dladdr, const void *addr, Dl_info *info) {
    Dl_info sinfo;
    int result = %orig(addr, &sinfo);

    if(result) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:sinfo.dli_fname length:strlen(sinfo.dli_fname)];

        if([_shadow isPathRestricted:path] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            HBLogDebug(@"%@: %@: %@", @"dyld", @"dladdr", path);
            return 0;
        }
    }

    return %orig;
}
%end

%group shadowhook_dyld_dlsym
%hookf(void *, dlsym, void *handle, const char *symbol) {
    void* addr = %orig;

    if(addr) {
        // Check origin of resolved symbol
        const char* image_path = dyld_image_path_containing_address(addr);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];
            
            if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
                HBLogDebug(@"%@: %@: %@", @"dlsym", @"restricted symbol lookup", @(symbol));
                return NULL;
            }
        }
    }

    return addr;
}
%end

%group shadowhook_dyld_extra
%hookf(void, _dyld_register_func_for_add_image, void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    // Check who's interested in this...
    const char* image_path = dyld_image_path_containing_address(func);

    if(image_path) {
        NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

        HBLogDebug(@"%@: %@: %@", @"dyld", @"_dyld_register_func_for_add_image", image_name);

        if([_shadow isPathRestricted:image_name]) {
            return %orig;
        }

        // add to our collection
        NSMutableArray* _dyld_add_image;

        if(_shdw_dyld_add_image) {
            _dyld_add_image = [_shdw_dyld_add_image mutableCopy];
        } else {
            _dyld_add_image = [NSMutableArray new];
        }

        [_dyld_add_image addObject:@((unsigned long)func)];
        _shdw_dyld_add_image = [_dyld_add_image copy];
    }
}

%hookf(void, _dyld_register_func_for_remove_image, void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    // Check who's interested in this...
    const char* image_path = dyld_image_path_containing_address(func);

    if(image_path) {
        NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

        HBLogDebug(@"%@: %@: %@", @"dyld", @"_dyld_register_func_for_remove_image", image_name);

        if([_shadow isPathRestricted:image_name]) {
            return %orig;
        }

        // add to our collection
        NSMutableArray* _dyld_remove_image;

        if(_shdw_dyld_remove_image) {
            _dyld_remove_image = [_shdw_dyld_remove_image mutableCopy];
        } else {
            _dyld_remove_image = [NSMutableArray new];
        }

        [_dyld_remove_image addObject:@((unsigned long)func)];
        _shdw_dyld_remove_image = [_dyld_remove_image copy];
    }
}

// %hookf(bool, dyld_process_is_restricted) {
//     return true;
// }

// %hookf(bool, dyld_shared_cache_some_image_overridden) {
//     return false;
// }
%end

// #define PT_DENY_ATTACH  31
// typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
// ptrace_ptr_t ptrace = NULL;

// static int (*original_ptrace)(int _request, pid_t _pid, caddr_t _addr, int _data);
// static int replaced_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data) {
//     if(_request == PT_DENY_ATTACH) {
//         return 0;
//     }

//     return original_ptrace(_request, _pid, _addr, _data);
// }

void shadowhook_dyld(void) {
    // ptrace = (ptrace_ptr_t) dlsym(RTLD_SELF, "ptrace");
    // MSHookFunction(ptrace, replaced_ptrace, (void **) &original_ptrace);

    %init(shadowhook_dyld);
}

void shadowhook_dyld_extra(void) {
    %init(shadowhook_dyld_extra);
}

void shadowhook_dyld_symlookup(void) {
    %init(shadowhook_dyld_dlsym);
}

void shadowhook_dyld_updatelibs(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_image_count > 0) {
        // Check if we already have this lib.
        // If not, add it
        if(_shdw_dyld_collection) {
            for(NSDictionary* dylib in _shdw_dyld_collection) {
                if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                    // Already exists - skip function.
                    return;
                }
            }

            NSString* name = @(dyld_image_path_containing_address(mh));

            // Add if safe dylib.
            if(![_shadow isPathRestricted:name]) {
                NSMutableArray* _dyld_collection = [_shdw_dyld_collection mutableCopy];
            
                NSDictionary* dylib = @{
                    @"name" : name,
                    @"mach_header" : @((unsigned long) mh),
                    @"slide" : @((unsigned long) vmaddr_slide)
                };

                [_dyld_collection addObject:dylib];
                _shdw_dyld_collection = [_dyld_collection copy];
                _shdw_dyld_image_count = [_dyld_collection count];
            }
            return;
        }
    }
    
    _shdw_dyld_image_count = 0;
    NSMutableArray* _dyld_collection = [NSMutableArray new];

    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char* _name = _dyld_get_image_name(i);
        const struct mach_header* _mh = _dyld_get_image_header(i);
        intptr_t _slide = _dyld_get_image_vmaddr_slide(i);

        if([@(_name) isEqualToString:@""] || [_shadow isPathRestricted:@(_name)]) {
            // Got a filtered dylib.
            continue;
        }

        // Safe dylib. Add to our collection
        NSDictionary* dylib = @{
            @"name" : @(_name),
            @"mach_header" : @((unsigned long) _mh),
            @"slide" : @((unsigned long) _slide)
        };

        [_dyld_collection addObject:dylib];
    }

    _shdw_dyld_collection = [_dyld_collection copy];
    _shdw_dyld_image_count = [_dyld_collection count];
}

void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_image_count > 0) {
        // Check if we already have this lib.
        // If not, do nothing
        if(_shdw_dyld_collection) {
            uint32_t i = 0;
            for(NSDictionary* dylib in _shdw_dyld_collection) {
                if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                    // Remove this from our collection
                    NSMutableArray* _dyld_collection = [_shdw_dyld_collection mutableCopy];
                    [_dyld_collection removeObjectAtIndex:i];

                    _shdw_dyld_collection = [_dyld_collection copy];
                    _shdw_dyld_image_count = [_dyld_collection count];
                    return;
                }

                i++;
            }
        }
    }
}

void shadowhook_dyld_shdw_add_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_add_image) {
        // Get the added image path.
        const char* image_path = dyld_image_path_containing_address(mh);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

            if([_shadow isPathRestricted:image_name]) {
                // Don't call any event handlers.
                return;
            }
        }

        // Call event handlers.
        for(NSNumber* func_ptr in _shdw_dyld_add_image) {
            void (*func)(const struct mach_header*, intptr_t) = (void *)[func_ptr unsignedLongValue];
            func(mh, vmaddr_slide);
        }
    }
}

void shadowhook_dyld_shdw_remove_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_remove_image) {
        // Get the added image path.
        const char* image_path = dyld_image_path_containing_address(mh);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

            if([_shadow isPathRestricted:image_name]) {
                // Don't call any event handlers.
                return;
            }
        }

        // Call event handlers.
        for(NSNumber* func_ptr in _shdw_dyld_remove_image) {
            void (*func)(const struct mach_header*, intptr_t) = (void *)[func_ptr unsignedLongValue];
            func(mh, vmaddr_slide);
        }
    }
}
