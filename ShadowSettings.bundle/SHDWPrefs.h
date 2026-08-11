#import <Foundation/Foundation.h>

// Per-app preference read/write with global fallback.
// appID == nil means global-only access.
// Writes are not flushed per call (synchronize is unnecessary; cfprefsd
// handles cross-process visibility). Batch operations that must be durable
// before returning (preset apply, import, reset) synchronize explicitly.
id  SHDWReadAppPref(NSUserDefaults *prefs, NSString *appID, NSString *key);
void SHDWWriteAppPref(NSUserDefaults *prefs, NSString *appID, NSString *key, id v);

// Count enabled hook toggles (the canonical preset key set); appID nil counts the global settings, else per-app effective values.
NSUInteger SHDWCountEnabledHooks(NSUserDefaults *prefs, NSString *appID);

// Light haptic on user toggle flips, matching iOS 16+ Settings' switch
// feedback. Call from setPreferenceValue:forSpecifier:.
void SHDWToggleHaptic(void);
