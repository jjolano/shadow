#import <Foundation/Foundation.h>

BOOL SHDWAppEnabled(NSUserDefaults *prefs, NSString *appID);
void SHDWWriteAppEnabled(NSUserDefaults *prefs, NSString *appID, BOOL enabled);

// YES when the app has no explicit per-app activation (App_Enabled absent):
// the runtime falls back to the global toggle. Writing an explicit value
// (SHDWWriteAppEnabled) takes the app off "follow global".
BOOL SHDWAppFollowsGlobal(NSUserDefaults *prefs, NSString *appID);

// Clear the per-app activation override so the app follows the global toggle.
void SHDWClearAppEnabled(NSUserDefaults *prefs, NSString *appID);

// Aggressive detector neutralization, resolved like activation: a per-app
// override (Detector_Aggressive inside the app dict) falls back to the global
// Detector_Aggressive scalar when absent.
BOOL SHDWAppAggressive(NSUserDefaults *prefs, NSString *appID);
void SHDWWriteAppAggressive(NSUserDefaults *prefs, NSString *appID, BOOL aggressive);
// YES when the app has no explicit Detector_Aggressive override (follows global).
BOOL SHDWAppAggressiveFollowsGlobal(NSUserDefaults *prefs, NSString *appID);
// Drop the per-app Detector_Aggressive override so the app follows the global.
void SHDWClearAppAggressive(NSUserDefaults *prefs, NSString *appID);

// Light haptic on user toggle flips, matching iOS 16+ Settings' switch
// feedback. Call from setPreferenceValue:forSpecifier:.
void SHDWToggleHaptic(void);
