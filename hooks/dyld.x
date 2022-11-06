#import "hooks.h"

BOOL _dlerror = NO;

%group shadowhook_dyld
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    NSArray* backtrace = [NSThread callStackSymbols];
    const char* result = %orig(image_index);

    if(result) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:result length:strlen(result)];

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:backtrace]) {
            return "/.file";
        }
    }

    return result;
}

%hookf(char *, dlerror) {
    NSArray* backtrace = [NSThread callStackSymbols];
    char* result = %orig;

    if(result && _dlerror && ![_shadow isCallerTweak:backtrace]) {
        _dlerror = NO;
        return "error";
    }

    return result;
}

%hookf(void *, dlopen, const char *path, int mode) {
    NSArray* backtrace = [NSThread callStackSymbols];
    void* handle = %orig;

    if(handle && path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if(![image_name containsString:@"/"]) {
            // todo
        }

        if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:backtrace]) {
            _dlerror = YES;
            dlclose(handle);
            return NULL;
        }
    }

    return handle;
}

%hookf(bool, dlopen_preflight, const char *path) {
    NSArray* backtrace = [NSThread callStackSymbols];
    bool result = %orig;
    
    if(result && path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([image_name containsString:@"/"]) {
            if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:backtrace]) {
                return false;
            }
        } else {
            // todo
        }
    }

    return result;
}

// %hookf(int, dladdr, const void *addr, Dl_info *info) {
//     Dl_info sinfo;
//     int result = %orig(addr, &sinfo);

//     if(result) {
//         // NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:sinfo.dli_fname length:strlen(sinfo.dli_fname)];        
//     }

//     return %orig;
// }

%hookf(void *, dlsym, void *handle, const char *symbol) {
    NSArray* backtrace = [NSThread callStackSymbols];
    void* addr = %orig;

    if(addr) {
        // Check origin of resolved symbol
        Dl_info info;

        if(dladdr(addr, &info)) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info.dli_fname length:strlen(info.dli_fname)];
            
            if([_shadow isPathRestricted:image_name] && ![_shadow isCallerTweak:backtrace]) {
                HBLogDebug(@"%@: %@: %@", @"dlsym", @"restricted symbol lookup", @(symbol));
                return NULL;
            }
        }
    }

    return addr;
}
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

// static int (*original_dladdr)(const void *addr, Dl_info *info);
// static int replaced_dladdr(const void *addr, Dl_info *info) {
//     Dl_info sinfo;
//     int result = original_dladdr(addr, &sinfo);

//     if(result) {
//         NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:sinfo.dli_fname length:strlen(sinfo.dli_fname)];

//         if([_shadow isPathRestricted:path]) {
//             return 0;
//         }
//     }

//     return original_dladdr(addr, info);
// }

// int _dladdr(const void *addr, Dl_info *info) {
//     return original_dladdr(addr, info);
// }

void shadowhook_dyld(void) {
    // ptrace = (ptrace_ptr_t) dlsym(RTLD_SELF, "ptrace");
    // MSHookFunction(ptrace, replaced_ptrace, (void **) &original_ptrace);

    %init(shadowhook_dyld);

    // Manual hooks
    // MSHookFunction(dladdr, replaced_dladdr, (void **) &original_dladdr);
}
