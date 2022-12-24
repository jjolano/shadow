#import "ShadowService+Restriction.h"
#import "../apple_priv/NSTask.h"

@implementation ShadowService (Restriction)
+ (BOOL)isPathCompliant:(NSString *)path withRuleset:(NSDictionary *)ruleset {
    if(![path isAbsolutePath]) {
        // Don't handle relative paths
        return YES;
    }

    // Verify structure
    NSDictionary* ruleset_fss = ruleset[@"FileSystemStructure"];

    if(!ruleset_fss || ruleset_fss[path]) {
        // no need to check further
        return YES;
    }
    
    NSString* path_tmp = path;

    while(!ruleset_fss[path_tmp] && ![path_tmp isEqualToString:@"/"]) {
        path_tmp = [path_tmp stringByDeletingLastPathComponent];
    }

    NSArray* ruleset_fss_base = ruleset_fss[path_tmp];

    if(ruleset_fss_base) {
        BOOL compliant = NO;

        for(NSString* name in ruleset_fss_base) {
            NSString* ruleset_path = [path_tmp stringByAppendingPathComponent:name];

            if([path hasPrefix:ruleset_path]) {
                compliant = YES;
                break;
            }
        }

        if(!compliant) {
            NSLog(@"isPathCompliant: path '%@' not compliant (key: %@)", path, path_tmp);
            return NO;
        }
    }

    return YES;
}

+ (BOOL)isPathWhitelisted:(NSString *)path withRuleset:(NSDictionary *)ruleset {
    if(![path isAbsolutePath] || [path isEqualToString:@"/"]) {
        return NO;
    }

    // Check whitelisted exact paths
    NSSet* ruleset_wepath = ruleset[@"WhitelistExactPaths"];

    if(ruleset_wepath && [ruleset_wepath containsObject:path]) {
        return YES;
    }

    // Check whitelisted paths
    NSArray* ruleset_wpath = ruleset[@"WhitelistPaths"];

    if(ruleset_wpath) {
        for(NSString* wpath in ruleset_wpath) {
            if([path hasPrefix:wpath]) {
                return YES;
            }
        }
    }

    // Check whitelisted predicates
    NSPredicate* ruleset_wpred = ruleset[@"WhitelistPredicates"];

    if(ruleset_wpred && [ruleset_wpred evaluateWithObject:path]) {
        return YES;
    }

    // NSArray* ruleset_wpred = ruleset[@"WhitelistPredicates"];

    // if(ruleset_wpred) {
    //     for(NSString* wpred in ruleset_wpred) {
    //         NSPredicate* pred = [NSPredicate predicateWithFormat:wpred];
            
    //         if([pred evaluateWithObject:path]) {
    //             return YES;
    //         }
    //     }
    // }

    return NO;
}

+ (BOOL)isPathBlacklisted:(NSString *)path withRuleset:(NSDictionary *)ruleset {
    if(![path isAbsolutePath] || [path isEqualToString:@"/"]) {
        return NO;
    }

    // Check blacklisted exact paths
    NSSet* ruleset_bepath = ruleset[@"BlacklistExactPaths"];

    if(ruleset_bepath && [ruleset_bepath containsObject:path]) {
        return YES;
    }

    // Check blacklisted paths
    NSArray* ruleset_bpath = ruleset[@"BlacklistPaths"];

    if(ruleset_bpath) {
        for(NSString* bpath in ruleset_bpath) {
            if([path hasPrefix:bpath]) {
                return YES;
            }
        }
    }

    // Check blacklisted predicates
    NSPredicate* ruleset_bpred = ruleset[@"BlacklistPredicates"];

    if(ruleset_bpred && [ruleset_bpred evaluateWithObject:path]) {
        return YES;
    }

    // NSArray* ruleset_bpred = ruleset[@"BlacklistPredicates"];

    // if(ruleset_bpred) {
    //     for(NSString* bpred in ruleset_bpred) {
    //         NSPredicate* pred = [NSPredicate predicateWithFormat:bpred];
            
    //         if([pred evaluateWithObject:path]) {
    //             return YES;
    //         }
    //     }
    // }

    return NO;
}

+ (BOOL)isPathRestricted_db:(NSArray *)db withPath:(NSString *)path {
    NSArray* base_extra = @[
        @"/Library/Application Support",
        @"/usr/lib"
    ];

    BOOL restricted = [db containsObject:path];

    if(restricted) {
        restricted = ![base_extra containsObject:path];
    }

    return restricted;
}

+ (BOOL)isPathRestricted_dpkg:(NSString *)dpkgPath withPath:(NSString *)path {
    NSArray* base_extra = @[
        @"/Library/Application Support",
        @"/usr/lib"
    ];

    BOOL restricted = NO;

    // Call dpkg to see if file is part of any installed packages on the system.
    NSTask* task = [NSTask new];
    NSPipe* stdoutPipe = [NSPipe new];

    [task setLaunchPath:dpkgPath];
    [task setArguments:@[@"--no-pager", @"-S", path]];
    [task setStandardOutput:stdoutPipe];
    [task launch];
    [task waitUntilExit];

    NSLog(@"%@: %@", @"dpkg", path);

    if([task terminationStatus] == 0) {
        // Path found in dpkg database - exclude if base package is part of the package list.
        NSData* data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
        NSString* output = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
        NSArray* lines = [output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];

        for(NSString* line in lines) {
            NSArray* line_split = [line componentsSeparatedByString:@": "];

            if([line_split count] == 2) {
                NSString* line_packages = line_split[0];

                if([line_packages hasPrefix:@"local diversion"]) {
                    continue;
                }

                NSString* line_path = line_split[1];
                NSArray* line_packages_split = [line_packages componentsSeparatedByString:@", "];

                BOOL exception = [line_packages_split containsObject:@"base"] || [line_packages_split containsObject:@"firmware-sbin"];

                if(!exception) {
                    if([base_extra containsObject:line_path]) {
                        exception = YES;
                    }
                }

                restricted = !exception;
            }
        }
    }

    return restricted;
}

+ (NSArray *)getURLSchemes_db:(NSSet *)db {
    NSMutableSet* schemes = [NSMutableSet new];

    for(NSString* path in db) {
        if([path hasSuffix:@".app"]) {
            NSBundle* appBundle = [NSBundle bundleWithPath:path];

            if(!appBundle) {
                continue;
            }

            NSDictionary* plist = [appBundle infoDictionary];

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

    // Manual entry
    [schemes addObject:@"undecimus"];
    [schemes addObject:@"filza"];
    [schemes addObject:@"xina"];

    return [schemes allObjects];
}

+ (NSArray*)getURLSchemes_dpkg:(NSString *)dpkgPath {
    NSMutableSet* schemes = [NSMutableSet new];

    if(dpkgPath) {
        NSTask* task = [NSTask new];
        NSPipe* stdoutPipe = [NSPipe new];

        [task setLaunchPath:dpkgPath];
        [task setArguments:@[@"--no-pager", @"-S", @"*.app"]];
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
                    NSString* path = [line objectAtIndex:1];

                    if([path hasSuffix:@".app"]) {
                        NSBundle* appBundle = [NSBundle bundleWithPath:path];

                        if(!appBundle) {
                            continue;
                        }

                        NSDictionary* plist = [appBundle infoDictionary];

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
    }

    // Manual entry
    [schemes addObject:@"undecimus"];
    [schemes addObject:@"filza"];
    [schemes addObject:@"xina"];

    return [schemes allObjects];
}
@end
