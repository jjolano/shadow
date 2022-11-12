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
    if(b) {
        *b = NO;
    }

    if(![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return NO;
    }

    BOOL restricted = NO;

    // Hardcoded restricted paths
    // Probably going to be mostly /var stuff.
    NSArray<NSString *>* restrictedpaths = @[
        @"/Library/MobileSubstrate",
        @"/Library/Frameworks/",
        @"/usr/lib/TweakInject",
        @"/usr/lib/tweaks",
        @"/var/jb",
        @"/Library/dpkg",
        @"/Library/Activator",
        @"/Library/PreferenceLoader",
        @"/Library/SnowBoard",
        @"/Library/ControlCenter/",
        @"/Library/Flipswitch",
        @"/Library/LaunchDaemons/",
        @"/Library/Themes",
        @"/dev/dlci.",
        @"/dev/ptmx",
        @"/dev/kmem",
        @"/dev/mem",
        @"/dev/vn0",
        @"/dev/vn1",
        @"/lib",
        @"/boot",
        @"/etc/rc.d",
        @"/etc/shells",
        @"/etc/fstab",
        @"/etc/afp.conf",
        @"/etc/launchd.conf",
        @"/etc/profile",
        @"/var/stash",
        @"/var/binpack",
        @"/private/preboot/jb",
        @"/var/lib/",
        @"/var/log/",
        @"/var/cache/",
        @"/var/checkra1n.dmg",
        @"/binpack",
        @"/taurine",
        @"/auxfiles",
        @"/Library/Caches/cy-",
        @"/tmp/",
        @"/var/run/",
        @"/var/mobile/Library/Application Support/Containers/",
        @"/var/mobile/Library/Application Support/xyz.willy",
        @"/var/mobile/Library/Caches/",
        @"/var/mobile/Library/Cachespayment",
        @"/var/mobile/Library/Filza",
        @"/var/mobile/Library/Preferences/",
        @"/var/mobile/Library/ControlCenter/ModuleConfiguration_CCSupport.plist",
        @"/var/mobile/Library/SBSettings",
        @"/var/mobile/Library/Cydia",
        @"/var/mobile/Library/Logs/Cydia",
        @"/var/mobile/Library/Sileo",
        @"/var/mobile/.",
        @"/System/Library/PreferenceBundles/AppList.bundle",
        @"/."
    ];

    for(NSString* restrictedpath in restrictedpaths) {
        if([path isEqualToString:restrictedpath] || [path hasPrefix:restrictedpath]) {
            restricted = YES;
            break;
        }
    }

    if(!restricted) {
        // Call dpkg to see if file is part of any installed packages on the system.
        NSTask* task = [NSTask new];
        NSPipe* stdoutPipe = [NSPipe new];

        [task setLaunchPath:@"/usr/bin/dpkg-query"];
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
                            @"/usr/lib",
                            @"/var/.overprovisioning_file"
                        ];

                        for(NSString* base_extra_path in base_extra) {
                            if([base_extra_path isEqualToString:[result objectAtIndex:1]]) {
                                exception = YES;
                            }
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

    // Hardcoded whitelisted paths
    NSArray<NSString *>* safepaths = @[
        @"/var/mobile/Library/Preferences/.GlobalPreferences.plist",
        @"/var/mobile/Library/Preferences/com.apple",
        @"/var/mobile/Library/Preferences/Wallpaper.png",
        @"/var/mobile/Library/Caches/com.apple",
        @"/var/mobile/Library/Caches/.com.apple",
        @"/var/mobile/Library/Caches/Checkpoint.plist",
        @"/var/mobile/Library/Caches/CloudKit",
        @"/var/mobile/Library/Caches/Configuration",
        @"/var/mobile/Library/Caches/FamilyCircle",
        @"/var/mobile/Library/Caches/GameKit",
        @"/var/mobile/Library/Caches/GeoServices",
        @"/var/mobile/Library/Caches/MappedImageCache",
        @"/var/mobile/Library/Caches/mediaanalysisd-service",
        @"/var/mobile/Library/Caches/PassKit",
        @"/var/mobile/Library/Caches/rtcreportingd",
        @"/var/mobile/Library/Caches/sharedCaches",
        @"/var/mobile/Library/Caches/TelephonyUI",
        @"/var/mobile/Library/Caches/VoiceServices",
        @"/var/mobile/Library/Caches/VoiceTrigger",
        @"/tmp/com.apple",
        @"/var/mobile/.forward",
        @"/.ba",
        @"/.mb",
        @"/.file",
        @"/.Trashes"
    ];

    for(NSString* safepath in safepaths) {
        if([path isEqualToString:safepath] || [path hasPrefix:safepath]) {
            restricted = NO;
            break;
        }
    }

    return restricted;
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

        NSString* path = [rawPath stringByStandardizingPath];
        path = [path stringByResolvingSymlinksInPath];

        response = @{
            @"path" : path
        };
    } else if([name isEqualToString:@"isPathRestricted"]) {
        if(!userInfo) {
            return nil;
        }
        
        NSString* rawPath = userInfo[@"path"];

        if(!rawPath || [rawPath isEqualToString:@"/"] || [rawPath isEqualToString:@""]) {
            return nil;
        }

        // Preprocess path string
        NSString* path = [rawPath stringByStandardizingPath];

        if(![path isAbsolutePath]) {
            HBLogDebug(@"%@: %@", @"ignoring relative path", path);
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

        HBLogDebug(@"%@: %@", @"received path", path);

        // Check response cache for given path.
        NSNumber* responseCachePath = [responseCache objectForKey:path];

        if(responseCachePath) {
            return @{
                @"restricted" : responseCachePath
            };
        }
        
        // Recurse call into parent directories.
        NSString* pathParent = [path stringByDeletingLastPathComponent];
        NSDictionary* responseParent = [self handleMessageNamed:name withUserInfo:@{@"path" : pathParent}];

        if(responseParent && [responseParent[@"restricted"] boolValue]) {
            return responseParent;
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

        [responseCache setObject:@(restricted) forKey:path];
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
    }

    return self;
}
@end
