#import <Foundation/Foundation.h>

#import "../common.h"
#import <libSandy.h>
#import <dlfcn.h>

// Same source the framework uses for the executable path (Choicy-derived:
// least side effects possible — see Core+Utilities.m).
extern char*** _NSGetArgv();

// Marker symbol for dladdr: the payload (ShadowCore.dylib) is installed
// beside this stub, and dladdr on this symbol resolves the stub's own path.
__attribute__((visibility("default"))) void _shdw_payload_entry(void) {}

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

    // The harness verification app is its own test subject: it installs to
    // /Applications (rooted) or /var/jb/Applications (rootless) — both
    // denied below — so without this exception it can never be hooked and
    // its battery would always read all-GAP on-device.
    BOOL isShadowHarness = [bundleIdentifier isEqualToString:@"me.jjolano.shadow.harness"];

    if(!isShadowHarness && ([executablePath hasPrefix:@"/Applications"]
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

    // Load the payload (ShadowCore.dylib) from the same directory as this
    // stub. dladdr on our own symbol gives the stub's path; the payload is
    // installed beside it. On failure: log and return, never crash.
    Dl_info info;
    if(dladdr((void *)&_shdw_payload_entry, &info) && info.dli_fname) {
        NSString *dir = [[NSString stringWithUTF8String:info.dli_fname] stringByDeletingLastPathComponent];
        NSString *payloadPath = [dir stringByAppendingPathComponent:@"ShadowCore.dylib"];

        if(!dlopen([payloadPath UTF8String], RTLD_NOW)) {
            NSLog(@"[Shadow] payload load failed: %s", dlerror());
        }
    }
}
