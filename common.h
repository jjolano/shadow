#define BUNDLE_ID           "me.jjolano.shadow"
#define MACH_SERVICE_NAME   BUNDLE_ID ".service"
#define SHADOW_RULESETS     "/Library/Shadow/Rulesets"
#define SHADOW_DB_PLIST     SHADOW_RULESETS "/dpkgInstalled.plist"
#define SHADOW_PREFS_PLIST  "/var/mobile/Library/Preferences/" BUNDLE_ID ".plist"

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
