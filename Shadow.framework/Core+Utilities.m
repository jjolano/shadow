#import <Shadow/Core+Utilities.h>
#import <Shadow/Ruleset.h>
#import <RootBridge.h>

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

+ (NSDictionary *)generateDatabase {
    // Determine dpkg info database path.
    NSArray* dpkgInfoPaths = @[
        @"/Library/dpkg/info",
        @"/var/lib/dpkg/info"
    ];

    NSString* dpkgInfoPath = nil;

    for(NSString* path in dpkgInfoPaths) {
        NSString* path_r = [RootBridge getJBPath:path];

        if([[NSFileManager defaultManager] fileExistsAtPath:path_r]) {
            dpkgInfoPath = path_r;
            break;
        }
    }

    if(!dpkgInfoPath) {
        return nil;
    }

    // // Load standard (built-in) ruleset.
    // NSString* ruleset_path = [@SHADOW_RULESETS stringByAppendingPathComponent:@"StandardRules.plist"];
    // ShadowRuleset* ruleset = [ShadowRuleset rulesetWithPath:[RootBridge getJBPath:ruleset_path]];

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

                    if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
                        continue;
                    }

                    if([[path pathExtension] isEqualToString:@"app"]) {
                        NSBundle* appBundle = [NSBundle bundleWithPath:[RootBridge getJBPath:path]];

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

                    // if(ruleset && ![ruleset isPathCompliant:path]) {
                    //     continue;
                    // }
                    
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

    [db_exception addObjectsFromArray:filter_names];
    [db_installed minusSet:db_exception];

    NSPredicate* emoji = [NSPredicate predicateWithFormat:@"SELF LIKE '/System/Library/PrivateFrameworks/CoreEmoji.framework/*.lproj'"];
    NSPredicate* not_emoji = [NSCompoundPredicate notPredicateWithSubpredicate:emoji];
    
    [db_installed filterUsingPredicate:not_emoji];

    return @{
        @"RulesetInfo" : @{
            @"Name" : @"dpkg installed files",
            @"Author" : @"Shadow Service"
        },
        @"BlacklistExactPaths" : [db_installed allObjects],
        @"BlacklistURLSchemes" : [schemes allObjects]
    };
}

+ (NSArray *)filterPathArray:(NSArray *)array restricted:(BOOL)restricted options:(NSDictionary<NSString *, id> *)options {
    Shadow* shadow = [Shadow sharedInstance];
    __block BOOL _restricted = restricted;

    NSIndexSet* indexes = [array indexesOfObjectsPassingTest:^BOOL(id obj, NSUInteger idx, BOOL* stop) {
        if([obj isKindOfClass:[NSString class]]) {
            return [shadow isPathRestricted:obj options:options] == _restricted;
        }
        
        if([obj isKindOfClass:[NSURL class]]) {
            return [shadow isURLRestricted:obj options:options] == _restricted;
        }

        return NO;
    }];

    return [array objectsAtIndexes:indexes];
}
@end
