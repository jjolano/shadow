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

    if([self isAddrRestricted:ret_addr]) {
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
    return [self isPathRestricted:path resolve:YES];
}

- (BOOL)isPathRestricted:(NSString *)path resolve:(BOOL)resolve {
    if(!path || [path isEqualToString:@"/"] || [path length] == 0) {
        return NO;
    }

    if(![path isAbsolutePath]) {
        NSLog(@"%@: %@: %@", @"isPathRestricted", @"relative path", path);
        path = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:path];
    }

    if(resolve) {
        if(_service && (_enhancedPathResolve || [[self class] shouldResolvePath:path])) {
            NSLog(@"%@: %@: %@", @"isPathRestricted", @"resolving path", path);
            path = [_service resolvePath:path];
        }
    } else {
        if([path characterAtIndex:0] == '~') {
            path = [path stringByReplacingOccurrencesOfString:@"~mobile" withString:@"/var/mobile"];
            path = [path stringByReplacingOccurrencesOfString:@"~root" withString:@"/var/root"];
            path = [path stringByReplacingOccurrencesOfString:@"~" withString:realHomePath];
        }
    }

    path = [[self class] getStandardizedPath:path];

    // Extra tweak compatibility
    if(_tweakCompatibility) {
        if([path hasPrefix:@"/Library/Application Support"]) {
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

        return [self isPathRestricted:path];
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
