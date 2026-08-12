#import <Preferences/PSListController.h>

// Lists apps the crash watchdog is tracking (Shadow.dylib's ctor bumps a
// per-app CrashCount.<bundleID> = "count:timestamp" and skips the payload once
// count reaches SHADOW_CRASH_THRESHOLD). Lets the user clear a stuck app so
// Shadow retries it, individually or all at once.
@interface SHDWSafeModeListController : PSListController
@end
