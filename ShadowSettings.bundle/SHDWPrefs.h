#import <Foundation/Foundation.h>

BOOL SHDWAppEnabled(NSUserDefaults *prefs, NSString *appID);
void SHDWWriteAppEnabled(NSUserDefaults *prefs, NSString *appID, BOOL enabled);

// Light haptic on user toggle flips, matching iOS 16+ Settings' switch
// feedback. Call from setPreferenceValue:forSpecifier:.
void SHDWToggleHaptic(void);
