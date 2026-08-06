#import <stdio.h>
#import <unistd.h>
#import <Foundation/Foundation.h>

#import <Shadow.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/SystemRulesGenerator.h>

#import <RootBridge.h>

#import "../common.h"

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        if(argc == 1) {
            printf("shdw - command line utility for Shadow\n");
            printf("usage: %s [-g] | <path> [path [...]]\n", argv[0]);
            printf("\tpath: check if path is restricted\n");
            printf("\t-g: regenerate dpkg ruleset; system ruleset regenerated only when iOS version or snapshot changed\n");

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
            BOOL dpkg_ok = NO;

            if(ruleset_dpkg) {
                dpkg_ok = [ruleset_dpkg writeToFile:[RootBridge getJBPath:@(SHADOW_DB_PLIST)] atomically:NO];

                if(dpkg_ok) {
                    printf("successfully regenerated dpkg ruleset\n");
                } else {
                    fprintf(stderr, "error: failed to save generated ruleset\n");
                }
            } else {
                fprintf(stderr, "error: could not generate ruleset\n");
            }

            NSInteger system_result = [SystemRulesGenerator writeSystemRuleset];

            if(system_result == 1) {
                printf("successfully regenerated system ruleset\n");
            } else if(system_result == -1) {
                fprintf(stderr, "error: failed to generate system ruleset\n");
            }

            // Fail-soft: exit status reflects the dpkg ruleset only; postinst
            // depends on -g succeeding even if SystemRules generation fails.
            return dpkg_ok ? 0 : -1;
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
