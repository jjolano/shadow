#import "Shadow.h"
#import "Shadow+Utilities.h"

#import <sys/stat.h>
#import <dlfcn.h>
#import <pwd.h>

#import "../apple_priv/dyld_priv.h"

@implementation Shadow {
    ShadowService* service;
    NSArray* schemes;

    NSMutableDictionary* orig_funcs;

    // App-specific
    NSString* bundlePath;
    NSString* homePath;
    NSString* realHomePath;
}

- (void)setOrigFunc:(NSString *)fname withAddr:(void *)addr {
    [orig_funcs setValue:@((unsigned long)addr) forKey:fname];
}

- (void *)getOrigFunc:(NSString *)fname elseAddr:(void *)addr {
    NSNumber* result = [orig_funcs objectForKey:fname];

    if(result) {
        return (void *)[result unsignedLongValue];
    }

    return addr;
}

- (BOOL)isCallerTweak:(NSArray *)backtrace {
    void* ret_addr = __builtin_return_address(1);

    if([self isAddrRestricted:ret_addr]) {
        return YES;
    }

    bool skipped = false;

    for(NSNumber* sym_addr in backtrace) {
        if(!skipped) {
            // Skip the first entry
            skipped = true;
            continue;
        }

        void* ptr_addr = (void *)[sym_addr longLongValue];

        // Lookup symbol
        const char* image_path = dyld_image_path_containing_address(ptr_addr);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];
            
            if([self isPathRestricted:image_name]) {
                if([image_name hasSuffix:@"Shadow.dylib"]) {
                    // skip Shadow calls
                    continue;
                }

                return YES;
            }
        }
    }

    return NO;
}

- (BOOL)isAddrRestricted:(const void *)addr {
    if(addr) {
        // See if this address belongs to a restricted file.
        const char* image_path = dyld_image_path_containing_address(addr);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

            if([image_name hasPrefix:bundlePath]) {
                return NO;
            }

            if([self isPathRestricted:image_name]) {
                return YES;
            }
        }
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

    if([path characterAtIndex:0] == '~') {
        path = [path stringByReplacingOccurrencesOfString:@"~mobile" withString:@"/var/mobile"];
        path = [path stringByReplacingOccurrencesOfString:@"~root" withString:@"/var/root"];
        path = [path stringByReplacingOccurrencesOfString:@"~" withString:realHomePath];
    }

    if(![path isAbsolutePath]) {
        NSLog(@"%@: %@: %@", @"isPathRestricted", @"relative path", path);
        path = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:path];
    }

    if(resolve) {
        if(service && [[self class] shouldResolvePath:path lstat:[self getOrigFunc:@"lstat" elseAddr:lstat]]) {
            path = [service resolvePath:path];
        }
    }

    path = [[self class] getStandardizedPath:path];

    // Extra tweak compatibility
    if(_tweakCompatibility) {
        if([path hasPrefix:@"/Library/Application Support"]) {
            return NO;
        }
    }

    // Check if path is restricted from Shadow Service.
    if(service && [service isPathRestricted:path]) {
        NSLog(@"%@: %@: %@", @"isPathRestricted", @"restricted", path);
        return YES;
    }

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

        if([self isPathRestricted:path]) {
            return YES;
        }
    }

    if(schemes && [schemes containsObject:[url scheme]]) {
        return YES;
    }

    return NO;
}

- (void)setService:(ShadowService *)_service {
    if(_service) {
        service = _service;

        NSDictionary* versions = [service getVersions];

        if(versions) {
            NSLog(@"%@: %@", @"bypass version", versions[@"bypass_version"]);
            NSLog(@"%@: %@", @"api version", versions[@"api_version"]);
        }

        schemes = [service getURLSchemes];
        NSLog(@"%@: %@", @"url schemes", schemes);
    }
}

- (instancetype)init {
    if((self = [super init])) {
        orig_funcs = [NSMutableDictionary new];
        schemes = nil;
        bundlePath = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];
        homePath = NSHomeDirectory();
        realHomePath = @(getpwuid(getuid())->pw_dir);
        _tweakCompatibility = NO;
        service = nil;

        if([bundlePath hasPrefix:@"/private/var"]) {
            NSMutableArray* pathComponents = [[bundlePath pathComponents] mutableCopy];
            [pathComponents removeObjectAtIndex:1];
            bundlePath = [NSString pathWithComponents:pathComponents];
        }

        if([homePath hasPrefix:@"/User"]) {
            NSMutableArray* pathComponents = [[homePath pathComponents] mutableCopy];
            [pathComponents removeObjectAtIndex:1];
            [pathComponents removeObjectAtIndex:0];

            homePath = [realHomePath stringByAppendingPathComponent:[NSString pathWithComponents:pathComponents]];
        }
    }

    return self;
}

+ (instancetype)shadowWithService:(ShadowService *)_service {
    Shadow* shadow = [Shadow new];
    [shadow setService:_service];
    return shadow;
}
@end
