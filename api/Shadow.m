#import <HBLog.h>
#import <dlfcn.h>
#import <pwd.h>

#import <AppSupport/CPDistributedMessagingCenter.h>
#import <rocketbootstrap/rocketbootstrap.h>

#import "dyld_priv.h"
#import "Shadow.h"

@implementation Shadow {
    NSCache* responseCache;
    NSArray* schemes;
    CPDistributedMessagingCenter* center;

    BOOL tweakCompat;
    BOOL tweakCompatExtra;

    // App-specific
    NSString* bundlePath;
    NSString* homePath;
    NSString* realHomePath;
}

+ (BOOL)isPathSafe:(NSString *)path {
    // Handle /
    NSArray* whitelist_root = @[
        @"/.ba",
        @"/.file",
        @"/.fseventsd",
        @"/.mb",
        @"/Applications",
        @"/Developer",
        @"/Library",
        @"/System",
        @"/User",
        @"/bin",
        @"/cores",
        @"/dev",
        @"/etc",
        @"/private",
        @"/sbin",
        @"/tmp",
        @"/usr",
        @"/var"
    ];

    for(NSString* path_root in whitelist_root) {
        if([path isEqualToString:path_root]) {
            return YES;
        }
    }

    NSArray* whitelist_safe = @[
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
        @"/var/mobile/Library/Caches/Snapshots/com.apple",
        @"/tmp/com.apple",
        @"/var/mobile/.forward",
        @"/var/.overprovisioning_file",
        @"/var/mobile/Library/Saved Application State/com.apple",
        @"/var/mobile/Library/SplashBoard/Snapshots/com.apple",
        @"/var/mobile/Library/Cookies/com.apple",
        @"/etc/asl",
        @"/etc/fstab",
        @"/etc/group",
        @"/etc/hosts",
        @"/etc/master.passwd",
        @"/etc/networks",
        @"/etc/notify.conf",
        @"/etc/passwd",
        @"/etc/ppp",
        @"/etc/protocols",
        @"/etc/racoon",
        @"/etc/services",
        @"/etc/ttys",
        @"/Library/Application Support/AggregateDictionary",
        @"/Library/Application Support/BTServer",
        @"/var/log/asl",
        @"/var/log/com.apple",
        @"/var/log/ppp",
        @"/System/Library/LaunchDaemons/com.apple",
        @"/var/MobileAsset",
        @"/var/db/timezone",
        @"/usr/share/tokenizer"
    ];

    for(NSString* path_safe in whitelist_safe) {
        if([path hasPrefix:path_safe]) {
            return YES;
        }
    }

    return NO;
}

+ (BOOL)isPathHardRestricted:(NSString *)path {
    if(!path || ![path isAbsolutePath] || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    BOOL restricted = YES;

    // Handle /
    NSArray* whitelist_root = @[
        @"/.ba",
        @"/.file",
        @"/.fseventsd",
        @"/.mb",
        @"/Applications",
        @"/Developer",
        @"/Library",
        @"/System",
        @"/User",
        @"/bin",
        @"/cores",
        @"/dev",
        @"/etc",
        @"/private",
        @"/sbin",
        @"/tmp",
        @"/usr",
        @"/var"
    ];

    for(NSString* path_root in whitelist_root) {
        if([path hasPrefix:path_root]) {
            restricted = NO;
            break;
        }
    }

    if(restricted) {
        return YES;
    }

    // Handle common jailbreak paths, including rootless
    NSArray* blacklist_jb = @[
        @"/Library/MobileSubstrate",
        @"/usr/lib/TweakInject",
        @"/usr/lib/tweaks",
        @"/var/jb",
        @"/private/preboot/jb",
        @"/usr/lib/pspawn_payload",
        @"/var/containers/Bundle/iosbinpack64",
        @"/var/containers/Bundle/tweaksupport",
        @"/var/LIB",
        @"/var/ulb",
        @"/var/bin",
        @"/var/sbin",
        @"/var/Apps",
        @"/Library/Frameworks",
        @"/Library/Themes",
        @"/Library/ControlCenter",
        @"/Library/Activator",
        @"/Library/dpkg",
        @"/Library/PreferenceLoader",
        @"/Library/SnowBoard",
        @"/Library/LaunchDaemons/",
        @"/Library/Flipswitch",
        @"/Library/Switches",
        @"/Library/Caches/cy-",
        @"/dev/dlci.",
        @"/dev/ptmx",
        @"/dev/kmem",
        @"/dev/mem",
        @"/dev/vn0",
        @"/dev/vn1",
        @"/var/stash",
        @"/var/db/stash",
        @"/var/binpack",
        @"/var/checkra1n.dmg",
        @"/var/mobile/Library/Application Support/xyz.willy",
        @"/var/mobile/Library/Cachespayment",
        @"/var/mobile/Library/Filza",
        @"/var/mobile/Library/ControlCenter/ModuleConfiguration_CCSupport.plist",
        @"/var/mobile/Library/SBSettings",
        @"/var/mobile/Library/Cydia",
        @"/var/mobile/Library/Logs/Cydia",
        @"/var/mobile/Library/Sileo",
        @"/var/root/.",
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Applications/Zebra.app",
        @"/usr/lib/libhooker.dylib",
        @"/usr/lib/libsubstitute.dylib",
        @"/usr/lib/libsubstrate.dylib",
        @"/usr/libexec/cydia",
        @"/usr/share/terminfo",
        @"/usr/share/zsh",
        @"/usr/share/man",
        @"/usr/bin/sh",
        @"/usr/bin/nawk",
        @"/usr/bin/awk",
        @"/usr/bin/pico",
        @"/usr/bin/unrar",
        @"/usr/bin/[",
        @"/usr/bin/editor",
        @"/usr/local/lib/log",
        @"/usr/include/",
        @"/usr/lib/log/",
        @"/bin/sh",
        @"/System/Library/PreferenceBundles/AppList.bundle",
        @"/var/mobile/Library/Preferences/",
        @"/var/mobile/Library/Caches/",
        @"/var/mobile/Library/Caches/Snapshots/",
        @"/tmp/",
        @"/var/mobile/.",
        @"/var/.",
        @"/var/mobile/Library/Saved Application State/",
        @"/var/mobile/SplashBoard/Snapshots/",
        @"/var/mobile/Library/Cookies/",
        @"/etc/",
        @"/Library/Application Support/",
        @"/var/log/",
        @"/System/Library/LaunchDaemons/",
        @"/var/lib/cydia",
        @"/var/lib/apt",
        @"/var/cache/"
    ];

    for(NSString* path_jb in blacklist_jb) {
        if([path hasPrefix:path_jb]) {
            return YES;
        }
    }

    // Handle /var/run
    if([path hasPrefix:@"/var/run"] && [path hasSuffix:@".pid"]) {
        return YES;
    }

    return NO;
}

- (BOOL)isCallerTweak:(NSArray<NSNumber *>*)backtrace {
    void* ret_addr = __builtin_return_address(1);

    if(ret_addr) {
        const char* image_path = dyld_image_path_containing_address(ret_addr);

        if(image_path) {
            NSString* image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:image_path length:strlen(image_path)];

            if([self isPathRestricted:image_name]) {
                return YES;
            }
        }
    }

    if(tweakCompat) {
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
    }

    return NO;
}

- (NSString *)resolvePath:(NSString *)path {
    if(!center || !path) {
        return path;
    }

    NSDictionary* response = [center sendMessageAndReceiveReplyName:@"resolvePath" userInfo:@{
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
    if(!path || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    // Process path string from XPC (since we have hooked methods)
    if(resolve) {
        path = [self resolvePath:path];

        if(![path isAbsolutePath]) {
            path = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:path];
        }
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

    if([path hasPrefix:@"/User"]) {
        NSMutableArray* pathComponents = [[path pathComponents] mutableCopy];
        [pathComponents removeObjectAtIndex:1];
        [pathComponents removeObjectAtIndex:0];

        path = [realHomePath stringByAppendingPathComponent:[NSString pathWithComponents:pathComponents]];
    }

    // Extra tweak compatibility
    if(tweakCompatExtra && [path hasPrefix:@"/Library/Application Support"]) {
        return NO;
    }

    // Some quick whitelisting
    if([Shadow isPathSafe:path]) {
        return NO;
    }

    // Check if path is hard restricted
    if([Shadow isPathHardRestricted:path]) {
        return YES;
    }

    if([path hasPrefix:bundlePath]
    || ([path hasPrefix:homePath] && ![homePath isEqualToString:realHomePath])
    || [path hasPrefix:@"/System"]
    || [path hasPrefix:@"/var/containers"]
    || [path hasPrefix:@"/var/mobile/Containers"]) {
        return NO;
    }

    if(!center) {
        return NO;
    }

    // Check response cache for given path.
    NSNumber* responseCachePath = [responseCache objectForKey:path];

    if(responseCachePath) {
        return [responseCachePath boolValue];
    }
    
    // Recurse call into parent directories.
    NSString* pathParent = [path stringByDeletingLastPathComponent];
    BOOL isParentPathRestricted = [self isPathRestricted:pathParent resolve:NO];

    if(isParentPathRestricted) {
        return YES;
    }

    BOOL restricted = NO;

    // Check if path is restricted using XPC.
    NSDictionary* response = [center sendMessageAndReceiveReplyName:@"isPathRestricted" userInfo:@{
        @"path" : path
    }];

    if(response) {
        restricted = [response[@"restricted"] boolValue];
    }

    [responseCache setObject:@(restricted) forKey:path];
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

- (void)setTweakCompat:(BOOL)enabled {
    tweakCompat = enabled;
}

- (void)setTweakCompatExtra:(BOOL)enabled {
    tweakCompatExtra = enabled;
}

- (instancetype)init {
    if((self = [super init])) {
        responseCache = [NSCache new];
        schemes = @[@"cydia", @"sileo", @"zbra", @"filza"];
        bundlePath = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];
        homePath = NSHomeDirectory();
        realHomePath = @(getpwuid(getuid())->pw_dir);
        tweakCompat = YES;
        tweakCompatExtra = NO;

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

        // Initialize connection to shadowd.
        center = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];

        // Test communication to shadowd.
        if(center) {
            rocketbootstrap_distributedmessagingcenter_apply(center);

            NSDictionary* response;
            response = [center sendMessageAndReceiveReplyName:@"ping" userInfo:nil];

            if(response) {
                HBLogDebug(@"%@: %@", @"bypass version", [response objectForKey:@"bypass_version"]);
                HBLogDebug(@"%@: %@", @"api version", [response objectForKey:@"api_version"]);

                // Preload data from shadowd.
                response = [center sendMessageAndReceiveReplyName:@"getURLSchemes" userInfo:nil];

                if(response) {
                    schemes = [response objectForKey:@"schemes"];
                }
            } else {
                HBLogDebug(@"%@", @"failed to communicate with shadowd");
            }
        } else {
            HBLogDebug(@"%@", @"failed to init shadowd");
        }

        HBLogDebug(@"%@: %@", @"schemes", schemes);
        HBLogDebug(@"%@: %@", @"bundlePath", bundlePath);
        HBLogDebug(@"%@: %@", @"homePath", homePath);
        HBLogDebug(@"%@: %@", @"realHomePath", realHomePath);
    }

    return self;
}
@end
