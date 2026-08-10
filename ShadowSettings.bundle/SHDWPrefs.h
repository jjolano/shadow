#import <Foundation/Foundation.h>

// Per-app preference read/write with global fallback.
// appID == nil means global-only access.
id  SHDWReadAppPref(NSUserDefaults *prefs, NSString *appID, NSString *key);
void SHDWWriteAppPref(NSUserDefaults *prefs, NSString *appID, NSString *key, id v);

// Light haptic on user toggle flips, matching iOS 16+ Settings' switch
// feedback. Call from setPreferenceValue:forSpecifier:.
void SHDWToggleHaptic(void);
