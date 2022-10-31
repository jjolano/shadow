#import "hooks.h"

%group shadowhook_dyld
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *result = %orig(image_index);

    if(result) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:result length:strlen(result)];

        if([_shadow isPathRestricted:image_name]) {
            return %orig(0);
        }

        NSLog(@"%@: %@", @"_dyld_get_image_name", image_name);
    }

    return result;
}

%hookf(void *, dlopen, const char *path, int mode) {
    if(path && ![_shadow isCallerTweak:[NSThread callStackSymbols]]) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_shadow isPathRestricted:image_name]) {
            return NULL;
        }
    }

    return %orig;
}

%hookf(bool, dlopen_preflight, const char *path) {
    if(path && ![_shadow isCallerTweak:[NSThread callStackSymbols]]) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_shadow isPathRestricted:image_name]) {
            return false;
        }
    }

    return %orig;
}

// %hookf(int, dladdr, const void *addr, Dl_info *info) {
//     int result = %orig(addr, info);

//     if(result && info) {
//         NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strlen(info->dli_fname)];

//         if([_shadow isPathRestricted:path]) {
//             return 0;
//         }
//     }

//     return result;
// }

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if(symbol && ![_shadow isCallerTweak:[NSThread callStackSymbols]]) {
        NSString *sym = [NSString stringWithUTF8String:symbol];

        if([sym hasPrefix:@"MS"]
        || [sym hasPrefix:@"Sub"]
        || [sym hasPrefix:@"PS"]
        || [sym hasPrefix:@"rocketbootstrap"]
        || [sym hasPrefix:@"LH"]
        || [sym hasPrefix:@"LM"]
        || [sym hasPrefix:@"substitute_"]) {
            return NULL;
        }
    }

    return %orig;
}
%end

// static int (*original_dladdr)(const void *addr, Dl_info *info);
// static int replaced_dladdr(const void *addr, Dl_info *info) {
//     int result = original_dladdr(addr, info);

//     if(result && info) {
//         NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strlen(info->dli_fname)];

//         if([_shadow isPathRestricted:path]) {
//             return 0;
//         }
//     }

//     return result;
// }

void shadowhook_dyld(void) {
    %init(shadowhook_dyld);

    // Manual hooks
    // MSHookFunction(dladdr, replaced_dladdr, (void **) &original_dladdr);
}
