#import <HBLog.h>

#import <AppSupport/CPDistributedMessagingCenter.h>
#import <rocketbootstrap/rocketbootstrap.h>

#import "Shadow.h"
#import "ShadowXPC.h"
#import "NSTask.h"

@implementation ShadowXPC {
    NSCache* responseCache;
    NSString* dpkgPath;
    CPDistributedMessagingCenter* center;
}

- (BOOL)isPathRestricted:(NSString *)path {
    if(!path || ![path isAbsolutePath] || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    // Check response cache for given path.
    NSNumber* responseCachePath = [responseCache objectForKey:path];

    if(responseCachePath) {
        return [responseCachePath boolValue];
    }
    
    // Recurse call into parent directories.
    NSString* pathParent = [path stringByDeletingLastPathComponent];
    BOOL isParentPathRestricted = [self isPathRestricted:pathParent];

    if(isParentPathRestricted) {
        return YES;
    }

    if(![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return NO;
    }

    BOOL restricted = NO;
    
    // Call dpkg to see if file is part of any installed packages on the system.
    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:dpkgPath];
    [task setArguments:@[@"-S", path]];
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

                if(!exception && [[path pathComponents] count] > 2) {
                    NSArray<NSString *>* base_extra = @[
                        @"/Library/Application Support",
                        @"/usr/lib"
                    ];

                    for(NSString* base_extra_path in base_extra) {
                        if([base_extra_path isEqualToString:[result objectAtIndex:1]]) {
                            exception = YES;
                        }
                    }
                }

                if(exception) {
                    restricted = NO;
                }

                break;
            }
        }
    }

    [responseCache setObject:@(restricted) forKey:path];
    return restricted;
}

- (NSArray<NSString *>*)getURLSchemes {
    NSMutableArray<NSString *>* schemes = [NSMutableArray new];

    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:dpkgPath];
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

                if([plistpath hasSuffix:@"Info.plist"]) {
                    NSDictionary* plist = [NSDictionary dictionaryWithContentsOfFile:plistpath];

                    if(plist && plist[@"CFBundleURLTypes"]) {
                        for(NSDictionary* type in plist[@"CFBundleURLTypes"]) {
                            if(type[@"CFBundleURLSchemes"]) {
                                for(NSString* scheme in type[@"CFBundleURLSchemes"]) {
                                    [schemes addObject:scheme];
                                }
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

    if([name isEqualToString:@"resolvePath"]) {
        if(!userInfo) {
            return nil;
        }

        NSString* rawPath = userInfo[@"path"];

        if(!rawPath) {
            return nil;
        }

        // Resolve and standardize path.
        NSString* path = [rawPath stringByStandardizingPath];

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

        response = @{
            @"path" : path
        };
    } else if([name isEqualToString:@"isPathRestricted"]) {
        if(!userInfo) {
            return nil;
        }
        
        NSString* path = userInfo[@"path"];

        if(!path || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
            return nil;
        }

        if(![path isAbsolutePath]) {
            HBLogDebug(@"%@: %@: %@", name, @"ignoring relative path", path);
            return nil;
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

        HBLogDebug(@"%@: %@", name, path);

        BOOL restricted = NO;
        
        // Check if path is restricted.
        if(!restricted) {
            restricted = [self isPathRestricted:path];
        }

        response = @{
            @"restricted" : @(restricted)
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
    } else if([name isEqualToString:@"ping"]) {
        HBLogDebug(@"%@: %@", name, @"received ping");

        response = @{
            @"ping" : @"pong",
            @"bypass_version" : @BYPASS_VERSION,
            @"api_version" : @API_VERSION
        };
    }

    return response;
}

- (instancetype)init {
    if((self = [super init])) {
        responseCache = [NSCache new];
        dpkgPath = [[NSFileManager defaultManager] fileExistsAtPath:@"/usr/bin/dpkg-query"] ? @"/usr/bin/dpkg-query" : nil;

        // Start shadowd.
		center = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];

        if(center) {
            rocketbootstrap_distributedmessagingcenter_apply(center);
            [center runServerOnCurrentThread];

            // Register messages.
            [center registerForMessageName:@"ping" target:self selector:@selector(handleMessageNamed:withUserInfo:)];
            [center registerForMessageName:@"isPathRestricted" target:self selector:@selector(handleMessageNamed:withUserInfo:)];
            [center registerForMessageName:@"getURLSchemes" target:self selector:@selector(handleMessageNamed:withUserInfo:)];
            [center registerForMessageName:@"resolvePath" target:self selector:@selector(handleMessageNamed:withUserInfo:)];

            // Unlock shadowd service.
            rocketbootstrap_unlock("me.jjolano.shadow");
        } else {
            return nil;
        }

        // Find dpkg if not at the usual place.
        if(!dpkgPath) {

        }
    }

    return self;
}
@end
