#import <Foundation/Foundation.h>

NSString *SHDWInstalledVersion(void);
void SHDWLocalizeSpecifiers(NSArray *specifiers, NSBundle *bundle, NSString *table);

BOOL SHDWAppEnabled(NSUserDefaults *prefs, NSString *appID);
void SHDWWriteAppEnabled(NSUserDefaults *prefs, NSString *appID, BOOL enabled);

// Shared by the summary, list badge, and whole-app Follow Global toggle.
BOOL SHDWAppIsCustomized(id appPrefs);
BOOL SHDWAppFollowsGlobal(NSUserDefaults *prefs, NSString *appID);
BOOL SHDWResetApp(NSUserDefaults *prefs, NSString *appID);

@class UIImage;
UIImage *SHDWSettingsSymbol(NSString *name);

// Clear per-app overrides so the app follows the global settings.
void SHDWClearAppOverrides(NSUserDefaults *prefs, NSString *appID);

// Aggressive detector neutralization, resolved like activation: a per-app
// override (Detector_Aggressive inside the app dict) falls back to the global
// Detector_Aggressive scalar when absent.
BOOL SHDWAppAggressive(NSUserDefaults *prefs, NSString *appID);
void SHDWWriteAppAggressive(NSUserDefaults *prefs, NSString *appID, BOOL aggressive);

// Light haptic on user toggle flips, matching iOS 16+ Settings' switch
// feedback. Call from setPreferenceValue:forSpecifier:.
void SHDWToggleHaptic(void);
