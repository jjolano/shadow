#import <sys/stat.h>
#import <dlfcn.h>
#import <pwd.h>

#import "Shadow.h"
#import "../apple_priv/dyld_priv.h"

@implementation Shadow {
    ShadowService* service;
    NSArray* schemes;

    BOOL tweakCompatExtra;
    NSMutableDictionary* orig_funcs;

    NSArray* whitelist_root;
    NSArray* whitelist_var;
    NSArray* whitelist_Library;
    NSArray* whitelist_usr;
    NSArray* whitelist_etc;

    NSArray* whitelist_safe;
    NSArray* blacklist_jb;
    NSArray* blacklist_name;

    // App-specific
    NSString* bundlePath;
    NSString* homePath;
    NSString* realHomePath;
}

- (void)setOrigFunc:(NSString *)fname withAddr:(void *)addr {
    [orig_funcs setValue:@((unsigned long)addr) forKey:fname];
}

- (void *)getOrigFunc:(NSString *)fname {
    NSNumber* result = [orig_funcs objectForKey:fname];

    if(result) {
        return (void *)[result unsignedLongValue];
    }

    return NULL;
}

- (BOOL)shouldResolvePath:(NSString *)path {
    if([path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    if([path characterAtIndex:0] == '~' || [[path lastPathComponent] isEqualToString:@".."] || [[path lastPathComponent] isEqualToString:@"."]) {
        // resolving relative path component
        return YES;
    }

    // check if path is symlink
    struct stat buf;
    int (*original_lstat)(const char* pathname, struct stat* buf) = [self getOrigFunc:@"lstat"];

    if(original_lstat && original_lstat([[NSFileManager defaultManager] fileSystemRepresentationWithPath:path], &buf) != -1 && buf.st_mode & S_IFLNK) {
        return YES;
    }

    // check path components recursively
    return [self shouldResolvePath:[path stringByDeletingLastPathComponent]];
}

- (BOOL)isPathSafe:(NSString *)path {
    if(!path || ![path isAbsolutePath] || [path isEqualToString:@""]) {
        return NO;
    }

    if([whitelist_root containsObject:path]
    || [whitelist_var containsObject:path]
    || [whitelist_Library containsObject:path]
    || [whitelist_usr containsObject:path]
    || [whitelist_etc containsObject:path]) {
        return YES;
    }

    for(NSString* path_safe in whitelist_safe) {
        if([path hasPrefix:path_safe]) {
            return YES;
        }
    }

    return NO;
}

- (BOOL)isPathHardRestricted:(NSString *)path {
    if(!path || ![path isAbsolutePath] || [path isEqualToString:@"/"] || [path isEqualToString:@""]) {
        return NO;
    }

    BOOL restricted = YES;

    if([path hasPrefix:@"/var/"]) {
        for(NSString* path_var in whitelist_var) {
            if([path hasPrefix:path_var]) {
                restricted = NO;
                break;
            }
        }
    } else if([path hasPrefix:@"/Library/"]) {
        for(NSString* path_Library in whitelist_Library) {
            if([path hasPrefix:path_Library]) {
                restricted = NO;
                break;
            }
        }
    } else if([path hasPrefix:@"/usr/"]) {
        for(NSString* path_usr in whitelist_usr) {
            if([path hasPrefix:path_usr]) {
                restricted = NO;
                break;
            }
        }
    } else if([path hasPrefix:@"/etc/"]) {
        for(NSString* path_etc in whitelist_etc) {
            if([path hasPrefix:path_etc]) {
                restricted = NO;
                break;
            }
        }
    } else {
        for(NSString* path_root in whitelist_root) {
            if([path hasPrefix:path_root]) {
                restricted = NO;
                break;
            }
        }
    }

    if(restricted) {
        return YES;
    }

    // Handle common jailbreak paths, including rootless
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

- (BOOL)isCallerTweak:(NSArray *)backtrace {
    void* ret_addr = __builtin_return_address(1);

    if(ret_addr) {
        const char* image_path = dyld_image_path_containing_address(ret_addr);

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

    if(![path isAbsolutePath] && [path characterAtIndex:0] != '~') {
        NSLog(@"%@: %@: %@", @"isPathRestricted", @"relative path", path);
        path = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:path];
    }

    if(resolve) {
        if(service && [self shouldResolvePath:path]) {
            path = [service resolvePath:path];
        }
    }

    if([path characterAtIndex:0] == '~') {
        path = [path stringByReplacingOccurrencesOfString:@"~mobile" withString:@"/var/mobile"];
        path = [path stringByReplacingOccurrencesOfString:@"~root" withString:@"/var/root"];
        path = [path stringByReplacingOccurrencesOfString:@"~" withString:realHomePath];
    }

    path = [path stringByReplacingOccurrencesOfString:@"/./" withString:@"/"];
    path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];

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

    // Extra tweak compatibility
    if(tweakCompatExtra && [path hasPrefix:@"/Library/Application Support"]) {
        return NO;
    }

    // Some quick whitelisting
    if([self isPathSafe:path]) {
        return NO;
    }

    // Check if path is hard restricted
    if([self isPathHardRestricted:path]) {
        return YES;
    }

    for(NSString* name in blacklist_name) {
        if([path containsString:name]) {
            return YES;
        }
    }

    if([path hasPrefix:@"/var/containers"]
    || [path hasPrefix:@"/var/mobile/Containers"]
    || [path hasPrefix:@"/System"]
    || [path hasPrefix:bundlePath]
    || [path hasPrefix:homePath]) {
        return NO;
    }

    // Check if path is restricted from ShadowService.
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

    if([schemes containsObject:[url scheme]]) {
        return YES;
    }

    return NO;
}

- (void)setTweakCompatExtra:(BOOL)enabled {
    tweakCompatExtra = enabled;
}

- (void)setService:(ShadowService *)_service {
    if(_service) {
        service = _service;

        NSDictionary* versions = [service getVersions];

        NSLog(@"%@: %@", @"bypass version", versions[@"bypass_version"]);
        NSLog(@"%@: %@", @"api version", versions[@"api_version"]);

        schemes = [service getURLSchemes];
        NSLog(@"%@: %@", @"url schemes", schemes);
    }
}

- (instancetype)init {
    if((self = [super init])) {
        orig_funcs = [NSMutableDictionary new];
        schemes = @[@"cydia", @"sileo", @"zbra", @"filza"];
        bundlePath = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];
        homePath = NSHomeDirectory();
        realHomePath = @(getpwuid(getuid())->pw_dir);
        tweakCompatExtra = NO;
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

        NSLog(@"%@: %@", @"bundlePath", bundlePath);
        NSLog(@"%@: %@", @"homePath", homePath);
        NSLog(@"%@: %@", @"realHomePath", realHomePath);

        whitelist_root = @[
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

        whitelist_var = @[
            @"/var/audit",
            @"/var/backups",
            @"/var/buddy",
            @"/var/cache",
            @"/var/containers",
            @"/var/db",
            @"/var/ea",
            @"/var/empty",
            @"/var/folders",
            @"/var/keybags",
            @"/var/Keychains",
            @"/var/lib",
            @"/var/local",
            @"/var/lock",
            @"/var/log",
            @"/var/logs",
            @"/var/Managed Preferences",
            @"/var/mobile",
            @"/var/MobileAsset",
            @"/var/MobileDevice",
            @"/var/MobileSoftwareUpdate",
            @"/var/msgs",
            @"/var/networkd",
            @"/var/personalized_factory",
            @"/var/preferences",
            @"/var/root",
            @"/var/run",
            @"/var/select",
            @"/var/spool",
            @"/var/staged_system_apps",
            @"/var/tmp",
            @"/var/vm",
            @"/var/wireless",
            @"/var/.overprovisioning_file",
            @"/var/.DocumentRevisions-V100",
            @"/var/.fseventsd",
            @"/var/installd",
            @"/var/hardware",
            @"/var/datamigrator",
            @"/var/protected"
        ];

        whitelist_Library = @[
            @"/Library/Application Support",
            @"/Library/Audio",
            @"/Library/Caches",
            @"/Library/Filesystems",
            @"/Library/Frameworks",
            @"/Library/Internet Plug-Ins",
            @"/Library/Keychains",
            @"/Library/LaunchAgents",
            @"/Library/LaunchDaemons",
            @"/Library/Logs",
            @"/Library/Managed Preferences",
            @"/Library/MobileDevice",
            @"/Library/MusicUISupport",
            @"/Library/Preferences",
            @"/Library/Printers",
            @"/Library/RegionFeatures",
            @"/Library/Ringtones",
            @"/Library/Updates",
            @"/Library/Wallpaper"
        ];

        whitelist_usr = @[
            @"/usr/bin",
            @"/usr/lib",
            @"/usr/libexec",
            @"/usr/sbin",
            @"/usr/share",
            @"/usr/standalone"
        ];

        whitelist_etc = @[
            @"/etc/asl",
            @"/etc/asl.conf",
            @"/etc/group",
            @"/etc/hosts",
            @"/etc/hosts.equiv",
            @"/etc/master.passwd",
            @"/etc/networks",
            @"/etc/notify.conf",
            @"/etc/passwd",
            @"/etc/ppp",
            @"/etc/protocols",
            @"/etc/racoon",
            @"/etc/services",
            @"/etc/ttys"
        ];

        whitelist_safe = @[
            @"/var/mobile/Library/Preferences/.GlobalPreferences.plist",
            @"/var/mobile/Library/Preferences/com.apple",
            @"/var/mobile/Library/Preferences/UITextInputContextIdentifiers.plist",
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
            @"/var/mobile/Library/Saved Application State/com.apple",
            @"/var/mobile/Library/SplashBoard/Snapshots/com.apple",
            @"/var/mobile/Library/Cookies/com.apple",
            @"/Library/Application Support/AggregateDictionary",
            @"/Library/Application Support/BTServer",
            @"/Library/LaunchDaemons/com.apple",
            @"/var/log/asl",
            @"/var/log/com.apple",
            @"/var/log/mDNSResponder",
            @"/var/log/ppp",
            @"/System/Library/LaunchDaemons/com.apple",
            @"/var/MobileAsset",
            @"/var/db/timezone",
            @"/usr/share/tokenizer",
            @"/bin/ps",
            @"/bin/df",
            @"/usr/lib/system"
        ];

        blacklist_jb = @[
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
            @"/Library/Frameworks/",
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
            @"/var/mobile/Library/Application Support/Containers/",
            @"/var/mobile/Library/Application Support/xyz.willy",
            @"/var/mobile/Library/Cachespayment",
            @"/var/mobile/Library/Filza",
            @"/var/mobile/Library/ControlCenter/ModuleConfiguration_CCSupport.plist",
            @"/var/mobile/Library/SBSettings",
            @"/var/mobile/Library/Cydia",
            @"/var/mobile/Library/Logs/Cydia",
            @"/var/mobile/Library/Sileo",
            @"/var/mobile/Library/.safeMode",
            @"/var/root/.",
            @"/Applications/Cydia.app",
            @"/Applications/Sileo.app",
            @"/Applications/Zebra.app",
            @"/usr/lib/libhooker",
            @"/usr/lib/libsubstitute",
            @"/usr/lib/libsubstrate",
            @"/usr/lib/substitute",
            @"/usr/lib/Substitute",
            @"/usr/lib/substrate",
            @"/usr/lib/Substrate",
            @"/usr/lib/tweakloader",
            @"/usr/lib/apt",
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
            @"/usr/include",
            @"/bin/",
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
            @"/var/lib/",
            @"/var/cache/",
            @"/User/"
        ];

        blacklist_name = @[
            @"LIAPP"
            // @"embedded.mobileprovision"
        ];
    }

    return self;
}

+ (instancetype)shadowWithService:(ShadowService *)_service {
    Shadow* shadow = [Shadow new];
    [shadow setService:_service];
    return shadow;
}
@end
