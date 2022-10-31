#import <HBLog.h>

#import "ShadowXPC.h"
#import "NSTask.h"

@implementation ShadowXPC {
    NSCache* responseCache;
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path isBase:NULL];
}

- (BOOL)isPathRestricted:(NSString *)path isBase:(BOOL *)b {
    if(b) {
        *b = NO;
    }

    HBLogDebug(@"%@: %@", @"dpkg", path);

    // Call dpkg to see if file is part of any installed packages on the system.
    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:@"/usr/bin/dpkg-query"];
    [task setArguments:@[@"-S", path]];
    [task setStandardOutput:stdoutPipe];
    [task launch];
    [task waitUntilExit];

    if([task terminationStatus] == 0) {
        // Path found in dpkg database - exclude if base package is part of the package list.
        NSData* data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
        NSString* output = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];

        NSArray<NSString *>* result = [output componentsSeparatedByString:@": "];

        if([result count] == 2) {
            NSArray<NSString *>* packages = [[result objectAtIndex:0] componentsSeparatedByString:@", "];

            if(![packages containsObject:@"base"]) {
                return YES;
            }

            if(b) {
                *b = YES;
            }
        }
    }

    return NO;
}

- (NSArray<NSString *>*)getDylibs {
    NSMutableArray<NSString *>* dylibs = [NSMutableArray new];

    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:@"/usr/bin/dpkg-query"];
    [task setArguments:@[@"-S", @".dylib"]];
    [task setStandardOutput:stdoutPipe];
    [task launch];
    [task waitUntilExit];

    if([task terminationStatus] == 0) {
        NSData* data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
        NSString* output = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];

        NSCharacterSet* separator = [NSCharacterSet newlineCharacterSet];
        NSArray<NSString *>* lines = [output componentsSeparatedByCharactersInSet:separator];

        for(NSString* entry in lines) {
            NSArray<NSString *>* line = [entry componentsSeparatedByString:@": "];

            if([line count] == 2) {
                [dylibs addObject:[line objectAtIndex:1]];
            }
        }
    }

    return [dylibs copy];
}

- (NSArray<NSString *>*)getURLSchemes {
    NSMutableArray<NSString *>* schemes = [NSMutableArray new];

    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:@"/usr/bin/dpkg-query"];
    [task setArguments:@[@"-S", @"app/Info.plist"]];
    [task setStandardOutput:stdoutPipe];
    [task launch];
    [task waitUntilExit];

    if([task terminationStatus] == 0) {
        NSData* data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
        NSString* output = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];

        NSCharacterSet* separator = [NSCharacterSet newlineCharacterSet];
        NSArray<NSString *>* lines = [output componentsSeparatedByCharactersInSet:separator];

        for(NSString* entry in lines) {
            NSArray<NSString *>* line = [entry componentsSeparatedByString:@": "];

            if([line count] == 2) {
                NSString* plistpath = [line objectAtIndex:1];
                NSDictionary* plist = [NSDictionary dictionaryWithContentsOfFile:plistpath];

                if(plist) {
                    for(NSDictionary* type in plist[@"CFBundleURLTypes"]) {
                        for(NSString* scheme in type[@"CFBundleURLSchemes"]) {
                            [schemes addObject:scheme];
                        }
                    }
                }
            }
        }
    }

    return [schemes copy];
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    NSDictionary* response = nil;

    if([name isEqualToString:@"ping"]) {
        HBLogDebug(@"%@: %@", name, @"received ping");

        response = @{
            @"ping" : @"pong"
        };
    } else if([name isEqualToString:@"isPathRestricted"]) {
        NSString* rawPath = userInfo[@"path"];

        if(!rawPath || [rawPath hasPrefix:@"-"] || [rawPath isEqualToString:@""]) {
            return nil;
        }

        HBLogDebug(@"%@: %@: %@", name, @"received path", rawPath);

        NSString* path = [rawPath stringByStandardizingPath];
        NSString* pathParent = [path stringByDeletingLastPathComponent];

        // Check response cache for given path.
        NSDictionary* responseCachePath = [responseCache objectForKey:path];

        if(responseCachePath) {
            return responseCachePath;
        }
        
        // Check all parent directories.
        NSDictionary* responseCacheParent = nil;

        do {
            responseCacheParent = [responseCache objectForKey:pathParent];

            if(responseCacheParent) {
                break;
            }

            pathParent = [pathParent stringByDeletingLastPathComponent];
        } while(![pathParent isEqualToString:@"/"] && ![pathParent isEqualToString:@""]);

        if(responseCacheParent) {
            return responseCacheParent;
        }

        // Check parent directory first.
        pathParent = [path stringByDeletingLastPathComponent];

        BOOL b = NO;
        BOOL restrictedParent = [self isPathRestricted:pathParent isBase:&b];

        response = @{
            @"restricted" : @(restrictedParent)
        };

        if(!b) {
            // Cache response if it's a completely clean/dirty path.
            [responseCache setObject:response forKey:pathParent];
        }

        if(!restrictedParent) {
            // Check full path.
            BOOL b = NO;
            BOOL restricted = [self isPathRestricted:path isBase:&b];

            if([[path pathComponents] count] == 2) {
                // Root
                restricted = !b;
            }

            response = @{
                @"restricted" : @(restricted)
            };

            [responseCache setObject:response forKey:path];
        }
    } else if([name isEqualToString:@"getDylibs"]) {
        HBLogDebug(@"%@: %@", name, @"list requested");

        NSArray<NSString *>* dylibs = [responseCache objectForKey:@"dylibs"];

        if(!dylibs) {
            dylibs = [self getDylibs];
            [responseCache setObject:dylibs forKey:@"dylibs"];
        }

        response = @{
            @"dylibs" : dylibs
        };
    } else if([name isEqualToString:@"getURLSchemes"]) {
        HBLogDebug(@"%@: %@", name, @"list requested");

        NSArray<NSString *>* schemes = [responseCache objectForKey:@"schemes"];

        if(!schemes) {
            schemes = [self getURLSchemes];
            [responseCache setObject:schemes forKey:@"schemes"];
        }

        response = @{
            @"schemes" : schemes
        };
    }

    return response;
}

- (instancetype)init {
    if((self = [super init])) {
        responseCache = [NSCache new];
    }

    return self;
}
@end
