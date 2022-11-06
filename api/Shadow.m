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

- (BOOL)isCallerTweak:(NSArray<NSString *>*)backtrace {
    for(NSString* line in backtrace) {
        NSArray* line_split = [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

        // Clean up output of callStackSymbols
        NSMutableArray* line_filtered = [NSMutableArray new];
        for(NSString* col in line_split) {
            if(![col isEqualToString:@""]) {
                [line_filtered addObject:col];
            }
        }

        NSString* dylib = line_filtered[1];

        if([dylib isEqualToString:@"???"] || ![dylib hasSuffix:@".dylib"]) {
            continue;
        }
        
        NSString* sym_addr = line_filtered[2];
        NSScanner* scanner = [NSScanner scannerWithString:sym_addr];

        unsigned long long num_addr = 0;
        void* ptr_addr = NULL;

        [scanner scanHexLongLong:&num_addr];
        ptr_addr = (void *)num_addr;

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
    if(!c || !path || [path isEqualToString:@""]) {
        return NO;
    }

    // Preprocess path string
    if(![path isAbsolutePath]) {
        HBLogDebug(@"%@: %@", @"relative path", path);
        return NO;
    }

    path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
    
    if([path hasPrefix:@"/private/var"] || [path hasPrefix:@"/private/etc"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];

        path = [NSString pathWithComponents:pathComponents];
    }

    // Excluded from checks
    NSString* bundlePath = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];

    if([bundlePath hasPrefix:@"/private/var"]) {
        NSMutableArray* pathComponents = [[bundlePath pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];

        bundlePath = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:bundlePath] || [path hasPrefix:@"/System/Library/PrivateFrameworks"] || [path hasPrefix:@"/private/var/mobile/Containers"] || [path hasPrefix:@"/private/var/containers"] || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }
    
    BOOL restricted = NO;

    if(!restricted) {
        // Check cache first
        NSDictionary* response = [responseCache objectForKey:path];

        // Check if path is restricted
        if(!response) {
            HBLogDebug(@"%@: %@", @"checking path", path);

            response = [c sendMessageAndReceiveReplyName:@"isPathRestricted" userInfo:@{
                @"path" : path
            }];

            if(response) {
                [responseCache setObject:response forKey:path];
            }
        }

        if(response) {
            restricted = [[response objectForKey:@"restricted"] boolValue];
        }
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
