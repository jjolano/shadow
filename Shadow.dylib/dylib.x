#import <Foundation/Foundation.h>

#import "../common.h"
#import <libSandy.h>
#import <dlfcn.h>

// Same source the framework uses for the executable path (Choicy-derived:
// least side effects possible — see Core+Utilities.m).
extern char*** _NSGetArgv();

%ctor {
    // Determine the application we're injected into.
    NSString* bundleIdentifier = [NSBundle mainBundle].bundleIdentifier;

    // Injected into SpringBoard: nothing to do — the hook_springboard group
    // was removed in v5, and vnode hiding is per-app only (SB holds no lease;
    // the daemon owns recovery).
    if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
        return;
    }

    NSString* executablePath = @(**_NSGetArgv());
    NSString* bundleType = [[executablePath stringByDeletingLastPathComponent] pathExtension];

    // Only load Shadow for applications in /var.
    if(![bundleType isEqualToString:@"app"]) {
        return;
    }

    // The verification apps are their own test subjects: they install to
    // /Applications (rooted) or /var/jb/Applications (rootless) — both
    // denied below — so without these exact exceptions they cannot be hooked.
    BOOL isVerificationApp = [bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"]
        || [bundleIdentifier isEqualToString:@"me.jjolano.dyldprobe"];

    if(!isVerificationApp && ([executablePath hasPrefix:@"/Applications"]
    || [executablePath hasPrefix:@"/System"]
    || [executablePath hasPrefix:@"/private/preboot"]
    || [executablePath hasPrefix:@"/var/jb"])) {
        return;
    }

    // Don't load in certain apps
    if([bundleIdentifier hasPrefix:@"com.opa334"]
    || [bundleIdentifier hasPrefix:@"org.coolstar"]
    || [bundleIdentifier hasPrefix:@"science.xnu"]
    || [bundleIdentifier hasPrefix:@"com.apple"]
    || [bundleIdentifier hasPrefix:@"com.samiiau.loader"]
    || [bundleIdentifier hasPrefix:@"com.llsc12.palera1nLoader"]) {
        return;
    }

    NSLog(@"loaded in app");

    // Load preferences (Foundation-only probe; the payload reads full prefs).
    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
        libSandy_applyProfile("ShadowSettings");
    }

    NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
    NSDictionary* app_settings = bundleIdentifier ? [defaults objectForKey:bundleIdentifier] : nil;

    // Per-app kill switch (see getPreferencesForIdentifier: in Settings.m).
    // Checked here rather than left to the payload's own gate so an excluded
    // app never dlopens ShadowCore at all — the point of the switch is to get
    // Shadow out of an app's way entirely.
    if([app_settings[@"App_Disabled"] boolValue]) {
        return;
    }

    if(![app_settings[@"App_Enabled"] boolValue] && ![defaults boolForKey:@"Global_Enabled"]) {
        return;
    }

    // Crash watchdog: count consecutive launches where the payload did not
    // complete its ctor (crash during load). After SHADOW_CRASH_THRESHOLD in
    // a row, skip the payload — the app keeps running unhooked instead of
    // dying at spawn. ShadowCore clears the counter when its ctor completes;
    // a stale counter (older than SHADOW_CRASH_DECAY_SECS) retries. Stored
    // inside the Shadow prefs plist — no separate file (detection vector).
    NSString* counterKey = shdw_crash_counter_key();
    if(counterKey) {
        NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:@SHADOW_PREFS_PLIST];
        int crashes = 0;
        NSString* counterStr = [defaults stringForKey:counterKey];
        if(counterStr) {
            NSArray* parts = [counterStr componentsSeparatedByString:@":"];
            if(parts.count == 2) {
                crashes = [parts[0] intValue];
                long long ts = [parts[1] longLongValue];
                if(ts > 0 && (long long)time(NULL) - ts > SHADOW_CRASH_DECAY_SECS) {
                    crashes = 0;   // stale — automatic retry
                }
            }
        }
        if(crashes >= SHADOW_CRASH_THRESHOLD) {
            NSLog(@"[Shadow] safe mode: %d consecutive crashes — payload skipped", crashes);
            return;
        }
        [defaults setObject:[NSString stringWithFormat:@"%d:%lld", crashes + 1, (long long)time(NULL)]
                    forKey:counterKey];
        [defaults synchronize];
    }

    // Load the payload (ShadowCore.dylib) from its fixed install path:
    // /usr/lib, prefixed by the package scheme (rootless/roothide stage
    // under /var/jb). The payload is NOT a DynamicLibraries tweak — it must
    // load only through this gated dlopen, never through the runtime's own
    // injection. On failure: log and return, never crash.
    NSString* payloadPath = [@THEOS_PACKAGE_INSTALL_PREFIX stringByAppendingString:@"/usr/lib/ShadowCore.dylib"];

    if(!dlopen([payloadPath UTF8String], RTLD_NOW)) {
        NSLog(@"[Shadow] payload load failed: %s", dlerror());
    }
}
