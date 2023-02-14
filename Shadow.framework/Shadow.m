#import "Shadow.h"
#import "Shadow+Utilities.h"

#import <sys/stat.h>
#import <dlfcn.h>
#import <pwd.h>

#import "../vendor/apple/dyld_priv.h"

@implementation Shadow {
    // App-specific
    NSString* bundlePath;
    NSString* homePath;
    NSString* realHomePath;
}

- (BOOL)isCallerTweak:(const void *)ret_addr {
    if(!ret_addr) ret_addr = __builtin_extract_return_addr(__builtin_return_address(1));

    if(ret_addr) {
        const char* ret_image_name = dyld_image_path_containing_address(ret_addr);

        if(ret_image_name) {
            if(strstr(ret_image_name, [bundlePath fileSystemRepresentation]) != NULL) {
                return NO;
            }

            return YES;
        }
    }

    return NO;
}

- (BOOL)isAddrRestricted:(const void *)addr {
    if(addr) {
        // See if this address belongs to a restricted file.
        const char* image_path = dyld_image_path_containing_address(addr);
        return [self isCPathRestricted:image_path];
    }

    return NO;
}

- (BOOL)isCPathRestricted:(const char *)path {
    if(path) {
        return [self isPathRestricted:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strnlen(path, PATH_MAX)]];
    }

    return NO;
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path options:nil];
}

- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options {
    if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
        return NO;
    }

    path = [path stringByExpandingTildeInPath];

    if([path characterAtIndex:0] == '~') {
        return NO;
    }

    if(![path isAbsolutePath]) {
        NSString* cwd = [options objectForKey:kShadowRestrictionWorkingDir];

        if(!cwd) {
            cwd = [[NSFileManager defaultManager] currentDirectoryPath];
        } else {
            if(![cwd isAbsolutePath]) {
                cwd = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:cwd];
            }
        }

        NSLog(@"%@: %@: %@", @"isPathRestricted", @"relative path", path);
        path = [cwd stringByAppendingPathComponent:path];
    }

    path = [[self class] getStandardizedPath:path];

    // Rootless mode: skip most checks outside of /var
    if(_rootlessMode) {
        if(![path hasPrefix:@"/var"] && ![path hasPrefix:@"/private/preboot"]) {
            return NO;
        }

        if([path hasPrefix:@"/var/jb"]) {
            return YES;
        }
    }

    // Check if path is restricted from Shadow Service.
    BOOL path_isOutsideSandbox = (![path hasPrefix:bundlePath] && ![path hasPrefix:homePath]);

    if(!_runningInApp || path_isOutsideSandbox) {
        // add file extension if missing in path
        NSString* file_ext = [options objectForKey:kShadowRestrictionFileExtension];

        if(file_ext) {
            if(![[path pathExtension] isEqualToString:file_ext]) {
                path = [path stringByAppendingFormat:@".%@", file_ext];
            }
        }
        
        // Skip checks if file doesn't exist
        if(![options objectForKey:kShadowRestrictionCheckFileExist] || [[options objectForKey:kShadowRestrictionCheckFileExist] boolValue]) {
            if(access([path fileSystemRepresentation], F_OK) != 0) {
                return NO;
            }

            // if(![[NSFileManager defaultManager] fileExistsAtPath:path]) {
            //     return YES;
            // }
        }
        
        if(![_service isPathCompliant:path]) {
            return YES;
        }

        if([_service isPathRestricted:path]) {
            NSLog(@"%@: %@: %@", @"isPathRestricted", @"restricted", path);
            return YES;
        }
    }

    // Check resolved path.
    if(![options objectForKey:kShadowRestrictionEnableResolve] || [[options objectForKey:kShadowRestrictionEnableResolve] boolValue]) {
        NSString* resolved_path = [_service resolvePath:path];

        NSMutableDictionary* opt = [NSMutableDictionary dictionaryWithDictionary:options];
        [opt setObject:@(NO) forKey:kShadowRestrictionEnableResolve];

        if([self isPathRestricted:resolved_path options:[opt copy]]) {
            return YES;
        }
    }

    if(path_isOutsideSandbox) {
        NSLog(@"%@: %@: %@", @"isPathRestricted", @"allowed", path);
    }

    return NO;
}

- (BOOL)isURLRestricted:(NSURL *)url {
    return [self isURLRestricted:url options:nil];
}

- (BOOL)isURLRestricted:(NSURL *)url options:(NSDictionary<NSString *, id> *)options {
    if(!url) {
        return NO;
    }

    if([url isFileURL]) {
        NSString *path = [url path];

        if([url isFileReferenceURL]) {
            NSURL *surl = [url standardizedURL];

            if(surl) {
                path = [surl path];
            }
        }

        return [self isPathRestricted:path options:options];
    }

    if([_service isURLSchemeRestricted:[url scheme]]) {
        return YES;
    }

    return NO;
}

- (instancetype)init {
    if((self = [super init])) {
        bundlePath = [[[self class] getExecutablePath] stringByDeletingLastPathComponent];
        homePath = NSHomeDirectory();
        realHomePath = @(getpwuid(getuid())->pw_dir);
        _service = nil;
        _rootlessMode = NO;
        _runningInApp = NO;

        bundlePath = [[self class] getStandardizedPath:bundlePath];
        homePath = [[self class] getStandardizedPath:homePath];
        realHomePath = [[self class] getStandardizedPath:realHomePath];
    }

    return self;
}

+ (instancetype)shadowWithService:(ShadowService *)service {
    Shadow* shadow = [Shadow new];
    [shadow setService:service];
    return shadow;
}
@end
