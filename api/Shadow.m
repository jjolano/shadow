#import "Shadow.h"
#import "Shadow+Utilities.h"

#import <sys/stat.h>
#import <dlfcn.h>
#import <pwd.h>

#import "../apple_priv/dyld_priv.h"

@implementation Shadow {
    // App-specific
    NSString* bundlePath;
    NSString* homePath;
    NSString* realHomePath;
}

- (BOOL)isCallerTweak:(NSArray *)backtrace {
    void* ret_addr = __builtin_return_address(1);

    if([self isAddrRestricted:ret_addr]) {
        return YES;
    }

    if(backtrace) {
        NSString* self_image_name = nil;
        bool skipped = false;

        for(NSNumber* sym_addr in backtrace) {
            void* ptr_addr = (void *)[sym_addr unsignedLongValue];

            // Lookup symbol
            const char* image_path = dyld_image_path_containing_address(ptr_addr);

            if(image_path) {
                NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

                if(!skipped) {
                    // Skip the first entry
                    skipped = true;
                    self_image_name = [image_name copy];
                    continue;
                }
                
                if([self isPathRestricted:image_name]) {
                    if([image_name isEqualToString:self_image_name]) {
                        // skip Shadow calls
                        continue;
                    }

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
    if(!path || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    if(![path isAbsolutePath]) {
        NSLog(@"%@: %@: %@", @"isPathRestricted", @"relative path", path);
        path = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:path];
    }

    if(resolve) {
        if(_service && ([[self class] shouldResolvePath:path] || _enhancedPathResolve)) {
            NSLog(@"%@: %@: %@", @"isPathRestricted", @"resolving path", path);
            path = [_service resolvePath:path];
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
