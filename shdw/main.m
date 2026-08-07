#import <stdio.h>
#import <unistd.h>
#import <stdatomic.h>
#import <Foundation/Foundation.h>
#import <notify.h>

#import <Shadow.h>
#import <Shadow/Core+Utilities.h>
#import <Shadow/SystemRulesGenerator.h>

#import <RootBridge.h>

#import "../common.h"

// Watcher daemon (-d): regenerates the installed-apps ruleset when apps are
// installed or uninstalled. App installs arrive in bursts (restores), so each
// notification bumps a generation counter and only the event that stays idle
// for kWatcherDebounceNs actually regenerates.
static const int64_t kWatcherDebounceNs = 5 * NSEC_PER_SEC;

static void setup_watcher(void) {
    static int32_t notify_tokens[2];
    static dispatch_queue_t queue = nil;
    static _Atomic(uint64_t) generation = 0;

    queue = dispatch_queue_create("me.jjolano.shadow.watcher", NULL);
    atomic_store_explicit(&generation, 0, memory_order_relaxed);

    // Coalescing handler: schedule a debounced regeneration; a newer event
    // (seen != generation at fire time) cancels it.
    void (^onChange)(void) = ^{
        uint64_t seen = atomic_fetch_add_explicit(&generation, 1, memory_order_relaxed) + 1;

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, kWatcherDebounceNs), queue, ^{
            if(atomic_load_explicit(&generation, memory_order_relaxed) == seen) {
                NSInteger result = [SystemRulesGenerator writeInstalledAppsRuleset];

                if(result == 1) {
                    fprintf(stderr, "installed-apps ruleset regenerated\n");
                } else if(result == -1) {
                    fprintf(stderr, "error: failed to regenerate installed-apps ruleset\n");
                }
            }
        });
    };

    // Run once at startup: covers installs that happened while stopped and
    // the first-ever boot where postinst's -g already ran (harmless no-op).
    onChange();

    notify_register_dispatch("com.apple.mobile.application_installed", &notify_tokens[0], queue, ^(int token) {
        (void) token;
        onChange();
    });
    notify_register_dispatch("com.apple.mobile.application_uninstalled", &notify_tokens[1], queue, ^(int token) {
        (void) token;
        onChange();
    });

    fprintf(stderr, "shadow-watcher: watching app install/uninstall notifications\n");
}

int main(int argc, char *argv[], char *envp[]) {
    @autoreleasepool {
        if(argc == 1) {
            printf("shdw - command line utility for Shadow\n");
            printf("usage: %s [-g] | <path> [path [...]]\n", argv[0]);
            printf("\tpath: check if path is restricted\n");
            printf("\t-g: regenerate dpkg ruleset; system ruleset regenerated only when iOS version or snapshot changed\n");
            printf("\t-d: watcher daemon - regenerate installed-apps ruleset on app install/uninstall\n");

            return 0;
        }

        bool regenerateDb = false;
        bool watcherMode = false;

        int opt;
        while((opt = getopt(argc, argv, "gd")) != -1) {
            switch(opt) {
                case 'g':
                    regenerateDb = true;
                    break;

                case 'd':
                    watcherMode = true;
                    break;
            }
        }

        if(watcherMode) {
            setup_watcher();
            dispatch_main(); // never returns
            return 0;
        }

        if(regenerateDb) {
            NSDictionary* ruleset_dpkg = [Shadow generateDatabase];
            BOOL dpkg_ok = NO;

            if(ruleset_dpkg) {
                NSString* db_path = [RootBridge getJBPath:@(SHADOW_DB_PLIST)];
                // Atomic: serialize to a temp file in the same directory, then
                // rename() over the target. A crash mid-write leaves the
                // previous dpkg ruleset intact instead of a truncated plist.
                NSString* tmp_path = [db_path stringByAppendingString:@".tmp"];

                if([ruleset_dpkg writeToFile:tmp_path atomically:NO]) {
                    dpkg_ok = (rename([tmp_path UTF8String], [db_path UTF8String]) == 0);
                }

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

            NSInteger apps_result = [SystemRulesGenerator writeInstalledAppsRuleset];

            if(apps_result == 1) {
                printf("successfully regenerated installed-apps ruleset\n");
            } else if(apps_result == -1) {
                fprintf(stderr, "error: failed to generate installed-apps ruleset\n");
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
