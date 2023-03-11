#import <Shadow/Core+Utilities.h>
#import <Shadow/Ruleset.h>

#import "../vendor/apple/dyld_priv.h"
#import "../common.h"

extern char*** _NSGetArgv();

@implementation Shadow (Utilities)
+ (NSString *)getStandardizedPath:(NSString *)path {
    if(!path) {
        return path;
    }

    NSURL* url = [NSURL URLWithString:path];

    if(!url) {
        url = [NSURL fileURLWithPath:path];
    }

    NSString* standardized_path = [[url standardizedURL] path];

    if(standardized_path) {
        path = standardized_path;
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
    return mainBundle ? (__bridge NSString *)CFBundleGetIdentifier(mainBundle) : nil;
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

    // Load standard (built-in) ruleset.
    NSString* ruleset_path = [@SHADOW_RULESETS stringByAppendingPathComponent:@"StandardRules.plist"];
    ShadowRuleset* ruleset = [ShadowRuleset rulesetWithPath:[Shadow getJBPath:ruleset_path]];

    NSArray* db_list_skip = @[@"base.list", @"firmware-sbin.list"];

    NSMutableSet* db_installed = [NSMutableSet new];
    NSMutableSet* db_exception = [NSMutableSet new];
    NSMutableSet* schemes = [NSMutableSet new];

    // Iterate all list files in database.
    NSArray* db_files = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dpkgInfoPath isDirectory:YES] includingPropertiesForKeys:@[] options:0 error:nil];

    for(NSURL* db_file in db_files) {
        if([[db_file pathExtension] isEqualToString:@"list"]) {
            NSString* content = [NSString stringWithContentsOfURL:db_file encoding:NSUTF8StringEncoding error:nil];

            if(content) {
                // Read all lines
                NSArray* lines = [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

                for(NSString* line in lines) {
                    NSString* path = [self getStandardizedPath:line];

                    if(!path || ![path length] || [path isEqualToString:@"/"]) {
                        continue;
                    }

                    if([[path pathExtension] isEqualToString:@"app"]) {
                        NSBundle* appBundle = [NSBundle bundleWithPath:[self getJBPath:path]];

                        if(appBundle) {
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
                    }

                    if(ruleset && ![ruleset isPathCompliant:path]) {
                        continue;
                    }
                    
                    if([db_list_skip containsObject:[db_file lastPathComponent]]) {
                        [db_exception addObject:path];
                    } else {
                        [db_installed addObject:path];
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

    filter_names = [[db_exception allObjects] arrayByAddingObjectsFromArray:filter_names];

    for(NSString* name in filter_names) {
        [db_installed removeObject:name];
    }

    NSPredicate* emoji = [NSPredicate predicateWithFormat:@"SELF LIKE '/System/Library/PrivateFrameworks/CoreEmoji.framework/*.lproj'"];
    NSPredicate* not_emoji = [NSCompoundPredicate notPredicateWithSubpredicate:emoji];
    NSArray* filtered_db_installed = [[db_installed allObjects] filteredArrayUsingPredicate:not_emoji];

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
