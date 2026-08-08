#define BUNDLE_ID           "me.jjolano.shadow"
#define MACH_SERVICE_NAME   BUNDLE_ID ".service"
#define SHADOW_RULESETS     "/Library/Shadow/Rulesets"
#define SHADOW_DB_PLIST     SHADOW_RULESETS "/dpkgInstalled.plist"
#define SHADOW_PREFS_PLIST  "/var/mobile/Library/Preferences/" BUNDLE_ID ".plist"

#import <Foundation/Foundation.h>
#include <unistd.h>

// Crash watchdog: the stub (Shadow.dylib) increments a per-app counter
// before loading the payload; ShadowCore resets it when its ctor completes.
// After SHADOW_CRASH_THRESHOLD consecutive launches where the payload did
// not complete (crash during load), the stub skips it — the app keeps
// running unhooked instead of dying at spawn. The counter decays after
// SHADOW_CRASH_DECAY_SECS so a fixed update recovers automatically.
//
// The counter lives INSIDE the Shadow prefs plist (per-app key) — never a
// separate file: a standalone file in the prefs dir would be a detection
// vector (the daemon hides the plist itself, so a visible sibling file would
// stand out). The plist is a known Shadow artifact either way and is
// vnode-hidden. Value format: "<count>:<unixTimestamp>" (timestamp enables
// the decay without trusting the plist mtime, which settings writes touch).
#define SHADOW_CRASH_THRESHOLD 3
#define SHADOW_CRASH_DECAY_SECS (24 * 60 * 60)

static inline NSString* shdw_crash_counter_key(void) {
    NSString* bundleID = [NSBundle mainBundle].bundleIdentifier;
    return bundleID ? [NSString stringWithFormat:@"CrashCount.%@", bundleID] : nil;
}

#ifdef DEBUG
#define NSLog(...) NSLog(__VA_ARGS__)
#else
#define NSLog(...) (void)0
#endif

#ifndef kCFCoreFoundationVersionNumber_iOS_14_1
#define kCFCoreFoundationVersionNumber_iOS_14_1 1751.108
#endif

#ifndef kCFCoreFoundationVersionNumber_iOS_11_0
#define kCFCoreFoundationVersionNumber_iOS_11_0 1443.00
#endif
