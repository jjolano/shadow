#import <Foundation/Foundation.h>

BOOL SHDWAppEnabled(NSUserDefaults *prefs, NSString *appID);
void SHDWWriteAppEnabled(NSUserDefaults *prefs, NSString *appID, BOOL enabled);

// YES when the app has no explicit per-app activation (App_Enabled absent):
// the runtime falls back to the global toggle. Writing an explicit value
// (SHDWWriteAppEnabled) takes the app off "follow global".
BOOL SHDWAppFollowsGlobal(NSUserDefaults *prefs, NSString *appID);

// Clear the per-app activation override so the app follows the global toggle.
void SHDWClearAppEnabled(NSUserDefaults *prefs, NSString *appID);

// Light haptic on user toggle flips, matching iOS 16+ Settings' switch
// feedback. Call from setPreferenceValue:forSpecifier:.
void SHDWToggleHaptic(void);
