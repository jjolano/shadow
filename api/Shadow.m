#import <HBLog.h>
#import <dlfcn.h>

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
    for(NSNumber* sym_addr in backtrace) {
        void* ptr_addr = (void *)[sym_addr longLongValue];

        // Lookup symbol
        Dl_info info;
        if(dladdr(ptr_addr, &info)) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info.dli_fname length:strlen(info.dli_fname)];

            if([image_name hasSuffix:@"Shadow.dylib"]) {
                // skip Shadow calls
                continue;
            }
            
            if([self isPathRestricted:image_name]) {
                return YES;
            }
        }
    }

    return NO;
}

- (BOOL)isPathRestricted:(NSString *)path {
    path = [path stringByStandardizingPath];

    if(!c || !path || [path isEqualToString:@""]) {
        return NO;
    }

    // Preprocess path string
    if(![path isAbsolutePath]) {
        HBLogDebug(@"%@: %@", @"relative path", path);

        // reconstruct path
        NSString* cwd = [[NSFileManager defaultManager] currentDirectoryPath];
        NSMutableArray* pathComponents = [[cwd pathComponents] mutableCopy];
        [pathComponents addObjectsFromArray:[path pathComponents]];
        path = [NSString pathWithComponents:pathComponents];
        path = [path stringByStandardizingPath];
    }
    
    if([path hasPrefix:@"/private/var"] || [path hasPrefix:@"/private/etc"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        path = [NSString pathWithComponents:pathComponents];
        path = [path stringByStandardizingPath];
    }

    // Excluded from checks
    NSString* bundlePath = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];

    if([bundlePath hasPrefix:@"/private/var"]) {
        NSMutableArray* pathComponents = [[bundlePath pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];

        bundlePath = [NSString pathWithComponents:pathComponents];
    }

    // Tweaks shouldn't be installing new files to /System
    // Conditional of shame
    if([path hasPrefix:@"/System/Library/PreferenceBundles/AppList.bundle"]) {
        return YES;
    }

    if([path hasPrefix:bundlePath] || [path hasPrefix:@"/System"] || [path hasPrefix:@"/var/mobile/Containers"] || [path hasPrefix:@"/var/containers"] || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    // Check response cache for given path.
    NSDictionary* responseCachePath = [responseCache objectForKey:path];

    if(responseCachePath) {
        return [responseCachePath[@"restricted"] boolValue];
    }
    
    // Recurse call into parent directories.
    NSString* pathParent = [path stringByDeletingLastPathComponent];
    BOOL responseParent = [self isPathRestricted:pathParent];

    if(responseParent) {
        return YES;
    }

    // Check if path is restricted using XPC.
    BOOL restricted = NO;
    NSDictionary* response = [c sendMessageAndReceiveReplyName:@"isPathRestricted" userInfo:@{
        @"path" : path
    }];

    if(response) {
        restricted = [response[@"restricted"] boolValue];
        [responseCache setObject:response forKey:path];
    }

    return restricted;
}

- (BOOL)isURLRestricted:(NSURL *)url {
    url = [url standardizedURL];

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
