#import <stdio.h>
#import <unistd.h>
#import <Foundation/Foundation.h>

#import <Shadow.h>
#import <Shadow/Core+Utilities.h>

#import <RootBridge.h>

#import "../common.h"

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        if(argc == 1) {
            printf("shdw - command line utility for Shadow\n");
            printf("usage: %s [-g] | <path> [path [...]]\n", argv[0]);
            printf("\tpath: check if path is restricted\n");
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
            NSDictionary* ruleset_dpkg = [Shadow generateDatabase];

            if(ruleset_dpkg) {
                BOOL success = [ruleset_dpkg writeToFile:[RootBridge getJBPath:@(SHADOW_DB_PLIST)] atomically:NO];

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
