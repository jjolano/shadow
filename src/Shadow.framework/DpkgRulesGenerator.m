#import <Shadow/SystemRulesGenerator.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/JBPath.h>

#import "../common.h"

static BOOL IsShadowVerificationBundle(NSString* bundleID) {
    return [bundleID isEqualToString:@"me.jjolano.shadow.harness"]
        || [bundleID isEqualToString:@"me.jjolano.dyldprobe"]
        || [bundleID hasPrefix:@"me.jjolano.shadow.test."];
}

@implementation SystemRulesGenerator

+ (NSDictionary *)_generateDpkgRuleset {
    NSDictionary* database = nil;

    SHADOW_INTERNAL_SCOPE {
        NSString* dpkgInfoPath = nil;

        for(NSString* path in @[@"/Library/dpkg/info", @"/var/lib/dpkg/info"]) {
            NSString* rootedPath = JBPath(path);

            if([[NSFileManager defaultManager] fileExistsAtPath:rootedPath]) {
                dpkgInfoPath = rootedPath;
                break;
            }
        }

        if(!dpkgInfoPath) {
            return nil;
        }

        NSSet* skippedLists = [NSSet setWithObjects:@"base.list", @"firmware-sbin.list", nil];
        NSMutableSet* installed = [NSMutableSet new];
        NSMutableSet* exceptions = [NSMutableSet new];
        NSMutableSet* schemes = [NSMutableSet new];
        NSArray* files = [[NSFileManager defaultManager]
            contentsOfDirectoryAtURL:[NSURL fileURLWithPath:dpkgInfoPath isDirectory:YES]
            includingPropertiesForKeys:@[] options:0 error:nil];

        for(NSURL* file in files) {
            if(![[file pathExtension] isEqualToString:@"list"]) {
                continue;
            }

            // Per-file pool: the full file contents, the split line array and
            // every per-line standardized string are transient. Without this
            // they accumulate across the whole info dir alongside the growing
            // installed/exceptions/schemes sets (large generation-time peak).
            @autoreleasepool {
                NSString* content = [NSString stringWithContentsOfURL:file encoding:NSUTF8StringEncoding error:nil];

                for(NSString* line in [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
                    NSString* path = [Shadow getStandardizedPath:line];

                    if(!path || [path length] == 0 || [path isEqualToString:@"/"]) {
                        continue;
                    }

                    if([[path pathExtension] isEqualToString:@"app"]) {
                        NSDictionary* plist = [[NSBundle bundleWithPath:JBPath(path)] infoDictionary];

                        if(!IsShadowVerificationBundle([plist objectForKey:@"CFBundleIdentifier"])) {
                            for(NSDictionary* type in [plist objectForKey:@"CFBundleURLTypes"]) {
                                NSArray* appSchemes = [type objectForKey:@"CFBundleURLSchemes"];

                                if(appSchemes) {
                                    [schemes addObjectsFromArray:appSchemes];
                                }
                            }
                        }
                    }

                    [([skippedLists containsObject:[file lastPathComponent]] ? exceptions : installed) addObject:path];
                }
            }
        }

        [exceptions addObjectsFromArray:@[
            @"/.", @"/Library/Application Support", @"/usr/lib", @"/usr/libexec",
            @"/usr/lib/system", @"/var/mobile/Library/Caches", @"/var/mobile/Media",
            @"/System/Library/PrivateFrameworks/CoreEmoji.framework",
            @"/System/Library/PrivateFrameworks/CoreEmoji.framework/SearchEngineOverrideLists",
            @"/System/Library/PrivateFrameworks/CoreEmoji.framework/SearchModel-en",
            @"/System/Library/PrivateFrameworks/TextInput.framework"
        ]];
        [installed minusSet:exceptions];
        NSPredicate* emoji = [NSPredicate predicateWithFormat:
            @"SELF LIKE '/System/Library/PrivateFrameworks/CoreEmoji.framework/*.lproj'"];
        [installed filterUsingPredicate:[NSCompoundPredicate notPredicateWithSubpredicate:emoji]];

        // Sort the set-derived arrays: NSSet enumeration order is
        // nondeterministic, so unsorted output would differ run-to-run and
        // defeat the unchanged-content write gate below.
        database = @{
            @"RulesetInfo" : @{ @"Name" : @"dpkg installed files", @"Author" : @"Shadow Service" },
            @"BlacklistExactPaths" : [[installed allObjects] sortedArrayUsingSelector:@selector(compare:)],
            @"BlacklistURLSchemes" : [[schemes allObjects] sortedArrayUsingSelector:@selector(compare:)]
        };
    }

    return database;
}

+ (NSInteger)writeDpkgRuleset {
    NSDictionary* ruleset = [self _generateDpkgRuleset];

    if(!ruleset) {
        return -1;
    }

    NSInteger result = -1;

    SHADOW_INTERNAL_SCOPE {
        NSString* path = JBPath(@(SHADOW_DB_PLIST));

        // Skip the write when content is unchanged: the store reloads on any
        // ruleset-file mtime change, so a no-op rewrite churns every process's
        // decision caches for nothing. Sorted arrays above make the dict
        // comparison stable. (Mirrors writeInstalledAppsRuleset's gate.)
        NSDictionary* previous = [NSDictionary dictionaryWithContentsOfFile:path];

        if(previous && [previous isEqual:ruleset]) {
            result = 1;
        } else {
            [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent]
                withIntermediateDirectories:YES attributes:nil error:nil];
            result = [ruleset writeToFile:path atomically:YES] ? 1 : -1;
        }
    }

    return result;
}

@end
