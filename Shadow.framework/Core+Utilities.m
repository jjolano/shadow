#import <Shadow/Core+Utilities.h>
#import "../vendor/apple/dyld_priv.h"

extern char*** _NSGetArgv();

@implementation Shadow (Utilities)
+ (NSString *)getStandardizedPath:(NSString *)path {
    if(!path) {
        return path;
    }

    NSURL* url = [[NSURL URLWithString:path] standardizedURL];

    if(url) {
        path = [url path];
    }

    while([path containsString:@"/./"]) {
        path = [path stringByReplacingOccurrencesOfString:@"/./" withString:@"/"];
    }

    while([path containsString:@"//"]) {
        path = [path stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
    }

    if([path length] > 1) {
        if([path hasSuffix:@"/"]) {
            path = [path substringToIndex:[path length] - 1];
        }

        while([path hasSuffix:@"/."]) {
            path = [path stringByDeletingLastPathComponent];
        }
        
        while([path hasSuffix:@"/.."]) {
            path = [path stringByDeletingLastPathComponent];
            path = [path stringByDeletingLastPathComponent];
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

    return path;
}

// code from Choicy
//methods of getting executablePath and bundleIdentifier with the least side effects possible
//for more information, check out https://github.com/checkra1n/BugTracker/issues/343
+ (NSString *)getExecutablePath {
    char* executablePathC = **_NSGetArgv();
    return executablePathC ? @(executablePathC) : nil;
}

+ (NSString *)getBundleIdentifier {
    CFBundleRef mainBundle = CFBundleGetMainBundle();

    if(mainBundle != NULL) {
        CFStringRef bundleIdentifierCF = CFBundleGetIdentifier(mainBundle);
        return (__bridge NSString *)bundleIdentifierCF;
    }

    return nil;
}

+ (NSString *)getCallerPath {
    const void* ret_addr = __builtin_extract_return_addr(__builtin_return_address(0));

    if(ret_addr) {
        const char* ret_image_name = dyld_image_path_containing_address(ret_addr);

        if(ret_image_name) {
            return @(ret_image_name);
        }
    }

    return nil;
}

+ (BOOL)isJBRootless {
    static BOOL rootless = NO;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        NSString* caller_path = [self getCallerPath];
        rootless = !([caller_path hasPrefix:@"/Library"] || [caller_path hasPrefix:@"/usr"]);
    });

    return rootless;
}

+ (NSString *)getJBPath:(NSString *)path {
    if(![self isJBRootless] || !path || ![path isAbsolutePath] || [path hasPrefix:@"/var/jb"]) {
        return path;
    }

    return [@"/var/jb" stringByAppendingPathComponent:path];
}

+ (NSDictionary *)generateDatabase {
    // Determine dpkg info database path.
    NSString* dpkgInfoPath = [self getJBPath:@"/Library/dpkg/info"];

    if(![[NSFileManager defaultManager] fileExistsAtPath:dpkgInfoPath]) {
        return nil;
    }

    NSMutableSet* db_installed = [NSMutableSet new];
    NSMutableSet* db_exception = [NSMutableSet new];

    // Iterate all list files in database.
    NSArray* db_files = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dpkgInfoPath] includingPropertiesForKeys:@[] options:0 error:nil];

    for(NSURL* db_file in db_files) {
        if([db_file pathExtension] && [[db_file pathExtension] isEqualToString:@"list"]) {
            NSString* content = [NSString stringWithContentsOfURL:db_file encoding:NSUTF8StringEncoding error:nil];

            if(content) {
                // Read all lines
                NSArray* lines = [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

                if([[db_file lastPathComponent] isEqualToString:@"base.list"] || [[db_file lastPathComponent] isEqualToString:@"firmware-sbin.list"]) {
                    // exception
                    for(NSString* line in lines) {
                        NSString* standardized_line = [Shadow getStandardizedPath:line];

                        if(standardized_line && [standardized_line length]) {
                            [db_exception addObject:standardized_line];
                        }
                    }
                } else {
                    // installed
                    for(NSString* line in lines) {
                        NSString* standardized_line = [Shadow getStandardizedPath:line];

                        if(standardized_line && [standardized_line length]) {
                            [db_installed addObject:standardized_line];
                        }
                    }
                }
            }
        }
    }

    // filter installed ruleset
    NSArray* filter_names = @[
        @"/.",
        @"/Library/Application Support",
        @"/usr/lib",
        @"/usr/libexec",
        @"/usr/lib/system",
        @"/var/mobile/Library/Caches",
        @"/var/mobile/Media",
        @"/System/Library/PrivateFrameworks/CoreEmoji.framework",
        @"/System/Library/PrivateFrameworks/CoreEmoji.framework/SearchEngineOverrideLists",
        @"/System/Library/PrivateFrameworks/CoreEmoji.framework/SearchModel-en",
        @"/System/Library/PrivateFrameworks/TextInput.framework"
    ];

    for(NSString* name in filter_names) {
        [db_installed removeObject:name];
        [db_exception removeObject:name];
    }

    NSArray* filter_exception = [db_exception allObjects];

    for(NSString* name in filter_exception) {
        [db_installed removeObject:name];
    }

    NSArray* filtered_db_installed = [db_installed allObjects];

    NSPredicate* emoji = [NSPredicate predicateWithFormat:@"SELF LIKE '/System/Library/PrivateFrameworks/CoreEmoji.framework/*.lproj'"];
    NSPredicate* not_emoji = [NSCompoundPredicate notPredicateWithSubpredicate:emoji];
    filtered_db_installed = [filtered_db_installed filteredArrayUsingPredicate:not_emoji];

    // url schemes
    NSPredicate* system_apps_pred = [NSPredicate predicateWithFormat:@"SELF ENDSWITH[c] '.app'"];
    NSArray* system_apps = [filtered_db_installed filteredArrayUsingPredicate:system_apps_pred];
    NSMutableSet* schemes = [NSMutableSet new];

    for(NSString* app in system_apps) {
        NSBundle* appBundle = [NSBundle bundleWithPath:[self getJBPath:app]];

        if(!appBundle) {
            continue;
        }

        NSDictionary* plist = [appBundle infoDictionary];
        NSDictionary* urltypes = [plist objectForKey:@"CFBundleURLTypes"];

        if(urltypes) {
            for(NSDictionary* type in urltypes) {
                NSArray* urlschemes = [type objectForKey:@"CFBundleURLSchemes"];

                if(urlschemes) {
                    [schemes addObjectsFromArray:urlschemes];
                }
            }
        }
    }

    return @{
        @"RulesetInfo" : @{
            @"Name" : @"dpkg installed files",
            @"Author" : @"Shadow Service"
        },
        @"BlacklistExactPaths" : filtered_db_installed,
        @"BlacklistURLSchemes" : [schemes allObjects]
    };
}
@end
