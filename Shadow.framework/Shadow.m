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

- (BOOL)isCallerTweak:(NSArray *)backtrace {
    static const char* self_image_name = NULL;

    if(!self_image_name) {
        void* caller_addr = __builtin_extract_return_addr(__builtin_return_address(0));
        self_image_name = dyld_image_path_containing_address(caller_addr);
    }

    void* ret_addr = __builtin_extract_return_addr(__builtin_return_address(1));
    const char* ret_image_name = dyld_image_path_containing_address(ret_addr);

    if([self isCPathRestricted:ret_image_name] || strstr(ret_image_name, "/System") != NULL) {
        return YES;
    }

    if(backtrace) {
        for(NSNumber* sym_addr in backtrace) {
            void* ptr_addr = [sym_addr pointerValue];

            // Lookup symbol
            const char* image_path = dyld_image_path_containing_address(ptr_addr);

            if(image_path) {
                if(strcmp(image_path, self_image_name) == 0) {
                    continue;
                }
                
                if([self isCPathRestricted:image_path]) {
                    return YES;
                }
            }
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
        return [self isPathRestricted:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)]];
    }

    return NO;
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path options:nil];
}

- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options {
    if(!_restrictionEnabled || !path || [path isEqualToString:@"/"] || [path length] == 0) {
        return NO;
    }

    path = [path stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    if(![path isAbsolutePath]) {
        NSString* cwd = options[kShadowRestrictionWorkingDir];

        if(!cwd) {
            cwd = [[NSFileManager defaultManager] currentDirectoryPath];
        }

        NSLog(@"%@: %@: %@", @"isPathRestricted", @"relative path", path);
        path = [cwd stringByAppendingPathComponent:path];
    }

    BOOL resolve = _enhancedPathResolve;

    if(!resolve) {
        if(options && options[kShadowRestrictionEnableResolve]) {
            resolve = [options[kShadowRestrictionEnableResolve] boolValue];
        } else {
            resolve = YES;
        }
    }

    if(_enhancedPathResolve || (resolve && [[self class] shouldResolvePath:path])) {
        NSMutableDictionary* opt = [NSMutableDictionary dictionaryWithDictionary:options];
        [opt setObject:@(NO) forKey:kShadowRestrictionEnableResolve];

        if(_service && [self isPathRestricted:[_service resolvePath:path] options:[opt copy]]) {
            return YES;
        }
    }

    if([path characterAtIndex:0] == '~') {
        path = [path stringByReplacingOccurrencesOfString:@"~mobile" withString:@"/var/mobile"];
        path = [path stringByReplacingOccurrencesOfString:@"~root" withString:@"/var/root"];
        path = [path stringByReplacingOccurrencesOfString:@"~" withString:realHomePath];
    }

    path = [[self class] getStandardizedPath:path];

    // Extra tweak compatibility
    if(_tweakCompatibility) {
        if([path hasPrefix:@"/Library/Application Support"]
        || [path hasPrefix:@"/Library/Themes"]) {
            return NO;
        }
    }

    // Rootless shortcuts
    if(_rootlessMode) {
        if(![path hasPrefix:@"/var"] && ![path hasPrefix:@"/private/preboot"]) {
            return NO;
        }

        if([path hasPrefix:@"/var/jb"]) {
            return YES;
        }
    }

    // Exclude app bundle and data paths
    if(_runningInApp) {
        if([path hasPrefix:bundlePath] || [path hasPrefix:homePath]) {
            return NO;
        }
    }

    // Check if path is restricted from Shadow Service.
    if(_service && [_service isPathRestricted:path]) {
        NSLog(@"%@: %@: %@", @"isPathRestricted", @"restricted", path);
        return YES;
    }

    NSLog(@"%@: %@: %@", @"isPathRestricted", @"allowed", path);
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

        if(!options) {
            return [self isPathRestricted:path];
        }

        return [self isPathRestricted:path options:options];
    }

    if(_service && [_service isURLSchemeRestricted:[url scheme]]) {
        return YES;
    }

    return NO;
}

- (instancetype)init {
    if((self = [super init])) {
        bundlePath = [[NSBundle mainBundle] bundlePath];
        homePath = NSHomeDirectory();
        realHomePath = @(getpwuid(getuid())->pw_dir);
        _tweakCompatibility = NO;
        _service = nil;
        _rootlessMode = NO;
        _runningInApp = NO;
        _restrictionEnabled = YES;

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
