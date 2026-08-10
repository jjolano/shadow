#import "SHDWPrefs.h"

#import <UIKit/UIKit.h>

id SHDWReadAppPref(NSUserDefaults *prefs, NSString *appID, NSString *key) {
	if(appID) {
		NSDictionary* prefs_app = [prefs dictionaryForKey:appID];

		if(prefs_app && [prefs_app objectForKey:key]) {
			return prefs_app[key];
		}
	}

	// Options not overridden for this app inherit the global value.
	return [prefs objectForKey:key];
}

void SHDWWriteAppPref(NSUserDefaults *prefs, NSString *appID, NSString *key, id v) {
	if(appID) {
		NSDictionary* prefs_app = [prefs dictionaryForKey:appID];
		NSMutableDictionary* prefs_app_m = prefs_app ? [prefs_app mutableCopy] : [NSMutableDictionary new];

		prefs_app_m[key] = v;

		[prefs setObject:[prefs_app_m copy] forKey:appID];
	} else {
		[prefs setObject:v forKey:key];
	}

	[prefs synchronize];
}

void SHDWToggleHaptic(void) {
	// Fresh instance per event: toggle flips are rare, allocation cost is
	// irrelevant next to the impact itself.
	UIImpactFeedbackGenerator* generator = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
	[generator impactOccurred];
}
