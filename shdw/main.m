#include <stdio.h>
#include <unistd.h>

#import <Foundation/Foundation.h>

#import "../common.h"

#import <Shadow.h>
#import <Shadow/Core+Utilities.h>

static NSDictionary* generateDatabase(void) {
    // Determine dpkg info database path.
    NSString* dpkgInfoPath = [Shadow getJBPath:@"/Library/dpkg/info"];

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
        NSBundle* appBundle = [NSBundle bundleWithPath:[Shadow getJBPath:app]];

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

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        if(argc == 1) {
            printf("shdw - command line utility for Shadow\n");
            printf("usage: %s [-g] | <path> [path [...]]\n", argv[0]);
            printf("\t-g: regenerate dpkg installed ruleset\n");

            return 0;
        }

        bool regenerateDb = false;

        int opt;
        while((opt = getopt(argc, argv, "g")) != -1) {
            switch(opt) {
                case 'g':
                    regenerateDb = true;
                    break;
            }
        }

        if(regenerateDb) {
            NSDictionary* ruleset_dpkg = generateDatabase();

            if(ruleset_dpkg) {
                BOOL success = [ruleset_dpkg writeToFile:[Shadow getJBPath:@(SHADOW_DB_PLIST)] atomically:NO];

                if(success) {
                    printf("successfully regenerated dpkg ruleset\n");
                    return 0;
                } else {
                    fprintf(stderr, "error: failed to save generated ruleset\n");
                }
            } else {
                fprintf(stderr, "error: could not generate ruleset\n");
            }

            return -1;
        }

        Shadow* shadow = [Shadow sharedInstance];

        if(!shadow) {
            fprintf(stderr, "error: could not init Shadow\n");
            return -1;
        }

        for(int i = optind; i < argc; i++) {
            // ignore relative paths
            if(argv[i][0] != '/') {
                continue;
            }

            BOOL restricted = [shadow isCPathRestricted:argv[i]];
            printf("%s: %s\n", argv[i], restricted ? "restricted" : "allowed");
        }

        return 0;
    }
}
