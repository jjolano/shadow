#import <HBLog.h>
#import <dlfcn.h>

#import "dyld_priv.h"
#import "Shadow.h"

@implementation Shadow {
    NSCache* responseCache;
    NSArray<NSString *>* schemes;
    CPDistributedMessagingCenter* c;
}

- (void)setMessagingCenter:(CPDistributedMessagingCenter *)center {
    c = center;
}

- (void)setURLSchemes:(NSArray<NSString *>*)u {
    schemes = u;

    HBLogDebug(@"%@: %@", @"url schemes", schemes);
}

- (BOOL)isCallerTweak:(NSArray<NSNumber *>*)backtrace {
    void* ret_addr = __builtin_return_address(1);

    if(ret_addr) {
        const char* image_path = dyld_image_path_containing_address(ret_addr);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

            if([image_name hasSuffix:@".dylib"] && [self isPathRestricted:image_name] && [image_name hasSuffix:@"Shadow.dylib"]) {
                return YES;
            }
        }
    }

    for(NSNumber* sym_addr in backtrace) {
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

- (NSString *)resolvePath:(NSString *)path {
    if(!c || !path) {
        return path;
    }

    NSDictionary* response = [c sendMessageAndReceiveReplyName:@"resolvePath" userInfo:@{
        @"path" : path
    }];

    if(response) {
        return response[@"path"];
    }

    return path;
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
    if(!c || !path || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    NSDictionary* response;

    // Process path string from XPC (since we have hooked methods)
    if(resolve) {
        path = [self resolvePath:path];
    }

    if(![path isAbsolutePath]) {
        path = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:path];
    }

    // Tweaks shouldn't be installing new files to /System
    // Conditional of shame
    if([path hasPrefix:@"/System/Library/PreferenceBundles/AppList.bundle"]
    || ([path hasPrefix:@"/System/Library/LaunchDaemons/"] && ![path hasPrefix:@"/System/Library/LaunchDaemons/com.apple"])) {
        return YES;
    }

    if([path hasPrefix:[[NSBundle mainBundle] bundlePath]] || [path hasPrefix:@"/System"]) {
        return NO;
    }
    
    if([path hasPrefix:@"/private/var"] || [path hasPrefix:@"/private/etc"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:@"/var/tmp"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:@"/var/containers"] || [path hasPrefix:@"/var/mobile/Containers"]) {
        return NO;
    }

    // Check response cache for given path.
    NSDictionary* responseCachePath = [responseCache objectForKey:path];

    if(responseCachePath) {
        return [responseCachePath[@"restricted"] boolValue];
    }
    
    // Recurse call into parent directories.
    NSString* pathParent = [path stringByDeletingLastPathComponent];
    BOOL responseParent = [self isPathRestricted:pathParent resolve:NO];

    if(responseParent) {
        return YES;
    }

    // Check if path is restricted using XPC.
    BOOL restricted = NO;

    response = [c sendMessageAndReceiveReplyName:@"isPathRestricted" userInfo:@{
        @"path" : path
    }];

    if(response) {
        restricted = [response[@"restricted"] boolValue];
        [responseCache setObject:response forKey:path];
    }

    return restricted;
}

- (BOOL)isURLRestricted:(NSURL *)url {
    if(!url) {
        return NO;
    }

    NSArray* exceptions = @[@"http", @"https"];

    if([exceptions containsObject:[url scheme]]) {
        return NO;
    }

    BOOL restricted = NO;

    if([url isFileURL]) {
        NSString *path = [url path];

        if([url isFileReferenceURL]) {
            NSURL *surl = [url standardizedURL];

            if(surl) {
                path = [surl path];
            }
        }

        restricted = [self isPathRestricted:path];
    }

    if(!restricted && [schemes containsObject:[url scheme]]) {
        restricted = YES;
    }

    return restricted;
}

- (instancetype)init {
    if((self = [super init])) {
        responseCache = [NSCache new];
        schemes = @[];
        c = nil;
    }

    return self;
}
@end
