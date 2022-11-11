#import "hooks.h"

BOOL _shdw_dlerror = NO;
uint32_t _shdw_dyld_image_count = 0;
NSMutableArray* _shdw_dyld_collection = nil;
NSMutableArray* _shdw_dyld_add_image = nil;
NSMutableArray* _shdw_dyld_remove_image = nil;

%group shadowhook_dyld
%hookf(int32_t, NSVersionOfLinkTimeLibrary, const char* libraryName) {
    HBLogDebug(@"%@: %@: %s", @"dyld", @"NSVersionOfRunTimeLibrary", libraryName);
    return %orig;
}

%hookf(int32_t, NSVersionOfRunTimeLibrary, const char* libraryName) {
    HBLogDebug(@"%@: %@: %s", @"dyld", @"NSVersionOfRunTimeLibrary", libraryName);
    return %orig;
}

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
        return image_index < _shdw_dyld_image_count ? [_shdw_dyld_collection[image_index][@"name"] fileSystemRepresentation] : NULL;
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
            const char* image_path = dyld_image_path_containing_address(handle);

            if(image_path) {
                image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];
            }
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
            if(!dlopen(path, RTLD_NOLOAD)) {
                return false;
            }
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

    if(info) {
        memcpy(info, &sinfo, sizeof(Dl_info));
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
            HBLogDebug(@"%@: %@: %@", @"dlsym", @"restricted symbol lookup", @(symbol));
            return NULL;
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

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return %orig;
        }

        // add to our collection
        if(!_shdw_dyld_add_image) {
            _shdw_dyld_add_image = [NSMutableArray new];
        }

        [_shdw_dyld_add_image addObject:@((unsigned long)func)];
    }
}

%hookf(void, _dyld_register_func_for_remove_image, void (*func)(const struct mach_header* mh, intptr_t vmaddr_slide)) {
    // Check who's interested in this...
    const char* image_path = dyld_image_path_containing_address(func);

    if(image_path) {
        NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

        HBLogDebug(@"%@: %@: %@", @"dyld", @"_dyld_register_func_for_remove_image", image_name);

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:[NSThread callStackReturnAddresses]]) {
            return %orig;
        }

        // add to our collection
        if(!_shdw_dyld_remove_image) {
            _shdw_dyld_remove_image = [NSMutableArray new];
        }

        [_shdw_dyld_remove_image addObject:@((unsigned long)func)];
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
    if(_shdw_dyld_collection) {
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
            _shdw_dyld_image_count = [_shdw_dyld_collection count];
        }

        return;
    }
    
    _shdw_dyld_collection = [NSMutableArray new];

    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char* _name = _dyld_get_image_name(i);
        const struct mach_header* _mh = _dyld_get_image_header(i);
        intptr_t _slide = _dyld_get_image_vmaddr_slide(i);

        NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:_name length:strlen(_name)];

        if([image_name isEqualToString:@""] || [_shadow isPathRestricted:image_name]) {
            // Got a filtered dylib.
            continue;
        }

        // Safe dylib. Add to our collection
        NSDictionary* dylib = @{
            @"name" : image_name,
            @"mach_header" : @((unsigned long) _mh),
            @"slide" : @((unsigned long) _slide)
        };

        HBLogDebug(@"%@: %@: %@", @"dyld", @"adding lib (init)", image_name);

        [_shdw_dyld_collection addObject:dylib];
    }

    _shdw_dyld_image_count = [_shdw_dyld_collection count];
}

void shadowhook_dyld_updatelibs_r(const struct mach_header* mh, intptr_t vmaddr_slide) {
    if(_shdw_dyld_collection) {
        // Check if we already have this lib.
        // If not, do nothing
        for(NSDictionary* dylib in _shdw_dyld_collection) {
            if(dylib[@"mach_header"] && [dylib[@"mach_header"] unsignedLongValue] == (unsigned long) mh) {
                // Remove this from our collection
                HBLogDebug(@"%@: %@: %@", @"dyld", @"removing lib", dylib[@"name"]);

                [_shdw_dyld_collection removeObject:dylib];
                _shdw_dyld_image_count = [_shdw_dyld_collection count];

                return;
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
                HBLogDebug(@"%@: %@: %@", @"dyld", @"add_image stopped", image_name);
                return;
            }
        }

        // Call event handlers.
        HBLogDebug(@"%@: %@", @"dyld", @"add_image calling handlers");

        for(NSNumber* func_ptr in _shdw_dyld_add_image) {
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
        // Get the added image path.
        const char* image_path = dyld_image_path_containing_address(mh);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

            if([_shadow isPathRestricted:image_name]) {
                // Don't call any event handlers.
                HBLogDebug(@"%@: %@: %@", @"dyld", @"remove_image stopped", image_name);
                return;
            }
        }

        // Call event handlers.
        HBLogDebug(@"%@: %@", @"dyld", @"remove_image calling handlers");
        
        for(NSNumber* func_ptr in _shdw_dyld_remove_image) {
            void (*func)(const struct mach_header*, intptr_t) = (void *)[func_ptr unsignedLongValue];

            // Make sure this function still exists...
            const char* image_path = dyld_image_path_containing_address(func);

            if(image_path) {
                func(mh, vmaddr_slide);
            }
        }
    }
}
