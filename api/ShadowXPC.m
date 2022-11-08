#import <HBLog.h>

#import "Shadow.h"
#import "ShadowXPC.h"
#import "NSTask.h"

@implementation ShadowXPC {
    NSCache* responseCache;
}

- (BOOL)isPathRestricted:(NSString *)path {
    return [self isPathRestricted:path isBase:NULL];
}

- (BOOL)isPathRestricted:(NSString *)path isBase:(BOOL *)b {
    if(![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return NO;
    }

    if(b) {
        *b = NO;
    }

    BOOL restricted = NO;

    // Hardcoded restricted paths
    NSArray<NSString *>* restrictedpaths = @[
        @"/Library/MobileSubstrate",
        @"/usr/lib/TweakInject",
        @"/usr/lib/tweaks",
        @"/var/jb",
        @"/dev/ptmx",
        @"/dev/kmem",
        @"/dev/mem",
        @"/dev/vn0",
        @"/dev/vn1",
        @"/lib",
        @"/etc/rc.d",
        @"/etc/shells",
        @"/var/stash",
        @"/var/binpack",
        @"/private/preboot/jb",
        @"/var/lib/cydia",
        @"/var/lib/filza",
        @"/var/log/apt",
        @"/var/log/dpkg",
        @"/var/checkra1n.dmg",
        @"/binpack"
    ];

    for(NSString* restrictedpath in restrictedpaths) {
        if([path hasPrefix:restrictedpath]) {
            restricted = YES;
            break;
        }
    }

    if(!restricted) {
        // Call dpkg to see if file is part of any installed packages on the system.
        NSTask* task = [NSTask new];
        NSPipe* stdoutPipe = [NSPipe new];

        [task setLaunchPath:@"/usr/bin/env"];
        [task setArguments:@[@"dpkg-query", @"-S", path]];
        [task setStandardOutput:stdoutPipe];
        [task launch];
        [task waitUntilExit];

        HBLogDebug(@"%@: %@", @"dpkg", path);

        if([task terminationStatus] == 0) {
            // Path found in dpkg database - exclude if base package is part of the package list.
            NSData* data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
            NSString* output = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];

            NSCharacterSet* separator = [NSCharacterSet newlineCharacterSet];
            NSArray<NSString *>* lines = [output componentsSeparatedByCharactersInSet:separator];

            for(NSString* line in lines) {
                NSArray<NSString *>* result = [line componentsSeparatedByString:@": "];

                if([result count] == 2) {
                    NSArray<NSString *>* packages = [[result objectAtIndex:0] componentsSeparatedByString:@", "];
                    
                    restricted = YES;

                    BOOL exception = [packages containsObject:@"base"] || [packages containsObject:@"firmware-sbin"];

                    if(!exception) {
                        NSArray<NSString *>* base_extra = @[
                            @"/Library/Application Support",
                            @"/usr/lib",
                            @"/.ba",
                            @"/.mb",
                            @"/.file",
                            @"/bin/ps",
                            @"/bin/df"
                        ];

                        if([base_extra containsObject:[result objectAtIndex:1]]) {
                            exception = YES;
                        }
                    }

                    if(exception) {
                        if(b) {
                            // Package found, but path is also a part of base system.
                            *b = YES;
                        }
                    }
                }
            }
        }
    }

    return restricted;
}

- (NSArray<NSString *>*)getURLSchemes {
    NSMutableArray<NSString *>* schemes = [NSMutableArray new];

    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:@"/usr/bin/env"];
    [task setArguments:@[@"dpkg-query", @"-S", @"app/Info.plist"]];
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

                if([plistpath hasSuffix:@"Info.plist"]) {
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
    }

    return [schemes copy];
}

- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo {
    NSDictionary* response = nil;

    if([name isEqualToString:@"ping"]) {
        HBLogDebug(@"%@: %@", name, @"received ping");

        response = @{
            @"ping" : @"pong",
            @"bypass_version" : @BYPASS_VERSION,
            @"api_version" : @API_VERSION
        };
    } else if([name isEqualToString:@"isPathRestricted"]) {
        NSString* rawPath = userInfo[@"path"];

        if(!rawPath) {
            return nil;
        }

        // Preprocess path string
        NSString* path = [rawPath stringByStandardizingPath];

        if(![path isAbsolutePath]) {
            HBLogDebug(@"%@: %@", @"relative path", path);
            return nil;
        }
        
        if([path hasPrefix:@"/private/var"] || [path hasPrefix:@"/private/etc"]) {
            NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
            [pathComponents removeObjectAtIndex:1];

            path = [NSString pathWithComponents:pathComponents];
        }

        // Check response cache for given path.
        NSDictionary* responseCachePath = [responseCache objectForKey:path];

        if(responseCachePath) {
            return responseCachePath;
        }
        
        // Recurse call into parent directories.
        NSString* pathParent = [path stringByDeletingLastPathComponent];

        if(![path isEqualToString:@"/"]) {
            NSDictionary* responseParent = [self handleMessageNamed:name withUserInfo:@{@"path":pathParent}];

            if(responseParent && [responseParent[@"restricted"] boolValue]) {
                return responseParent;
            }
        }

        // Check if path is restricted.
        BOOL b = NO;
        BOOL restricted = [self isPathRestricted:path isBase:&b];

        if(restricted && b) {
            restricted = NO;
        }

        response = @{
            @"restricted" : @(restricted)
        };

        [responseCache setObject:response forKey:path];
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
