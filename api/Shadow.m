#import <HBLog.h>

#import "Shadow.h"

@implementation Shadow {
    NSCache* responseCache;
    NSArray<NSString *>* dylibs;
    NSArray<NSString *>* schemes;
    CPDistributedMessagingCenter* c;
}

- (void)setMessagingCenter:(CPDistributedMessagingCenter *)center {
    c = center;
}

- (void)setDylibs:(NSArray<NSString *>*)d {
    dylibs = d;
}

- (void)setURLSchemes:(NSArray<NSString *>*)u {
    schemes = u;
}

- (BOOL)isCallerTweak:(NSArray<NSString *>*)backtrace {
    for(NSString* entry in backtrace) {
        NSArray<NSString *>* line = [entry componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString* filename = [line objectAtIndex:2];

        if([filename isEqualToString:@""]) {
            filename = [line objectAtIndex:3];
        }

        // Exclusions
        if([filename isEqualToString:@"Shadow.dylib"] || ![filename hasSuffix:@".dylib"]) {
            continue;
        }

        if([dylibs containsObject:filename]) {
            HBLogDebug(@"%@: %@ (backtrace entry %@)", @"allowed dylib", filename, [line objectAtIndex:0]);
            return YES;
        }
    }

    return NO;
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(!c || !path || [path isEqualToString:@""]) {
        return NO;
    }

    // Preprocess path string
    path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
    
    if([path hasPrefix:@"/private"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];

        path = [NSString pathWithComponents:pathComponents];
    }

    // Excluded from checks
    NSString* bundlePath = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];

    if([bundlePath hasPrefix:@"/private"]) {
        NSMutableArray* pathComponents = [[bundlePath pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];

        bundlePath = [NSString pathWithComponents:pathComponents];
    }

    if([path hasPrefix:bundlePath] || [path hasPrefix:@"/var/mobile/Containers"] || [path hasPrefix:@"/System/Library/PrivateFrameworks"] || [path hasPrefix:@"/var/containers"]) {
        return NO;
    }

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

    BOOL restricted = NO;

    if(response) {
        restricted = [[response objectForKey:@"restricted"] boolValue];

        if(restricted && [self isCallerTweak:[NSThread callStackSymbols]]) {
            // Exclude if method call originates from a dpkg registered dylib
            // For tweak compatibility.
            restricted = NO;
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

    if([self isCallerTweak:[NSThread callStackSymbols]]) {
        return NO;
    }

    if([schemes containsObject:[url scheme]]) {
        return YES;
    }

    return NO;
}

- (instancetype)init {
    if((self = [super init])) {
        responseCache = [NSCache new];
        dylibs = @[];
        c = nil;
    }

    return self;
}
@end
