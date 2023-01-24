#include <stdio.h>
#include <unistd.h>

#import <Foundation/Foundation.h>

#import <Shadow/common.h>
#import <Shadow/Shadow.h>
#import <Shadow/ShadowService+Database.h>

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        if(argc == 1) {
            printf("shdw - command line utility for Shadow\n");
            printf("usage: %s [-g]|[-s] <path> [path [...]]\n", argv[0]);
            printf("\t-s: use Shadow Service\n");
            printf("\t-g: regenerate dpkg installed ruleset\n");

            return 0;
        }

        bool useService = false;
        bool regenerateDb = false;

        int opt;

        while((opt = getopt(argc, argv, "sg")) != -1) {
            switch(opt) {
                case 's':
                    useService = true;
                    break;
                case 'g':
                    regenerateDb = true;
                    break;
            }
        }

        if(regenerateDb) {
            NSDictionary* ruleset_dpkg = [ShadowService generateDatabase];

            if(ruleset_dpkg) {
                BOOL success = [ruleset_dpkg writeToFile:@SHADOW_DB_PLIST atomically:NO];

                if(!success) {
                    success = [ruleset_dpkg writeToFile:@("/var/jb" SHADOW_DB_PLIST) atomically:NO];
                }

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

        ShadowService* srv = [ShadowService new];

        if(!srv) {
            fprintf(stderr, "error: could not init ShadowService\n");
            return -1;
        }

        if(useService) {
            [srv connectService];
        } else {
            [srv loadRulesets];
        }

        Shadow* shadow = [Shadow shadowWithService:srv];

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
