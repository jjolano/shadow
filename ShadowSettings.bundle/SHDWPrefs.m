#import "SHDWPrefs.h"

#import <UIKit/UIKit.h>
#import <Shadow/HookConfiguration.h>

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
}

NSUInteger SHDWCountEnabledHooks(NSUserDefaults *prefs, NSString *appID) {
	NSUInteger count = 0;

	// The canonical hook-key set is the preset keys (every Hook_* toggle plus
	// PseudoSandboxMode); Global_Enabled / HK_Library / MemoryLevelHiding are not
	// user-facing hook toggles and must not inflate the count.
	for(NSString* key in SHDWPresetStandard()) {
		BOOL enabled = appID
			? [SHDWReadAppPref(prefs, appID, key) boolValue]
			: [prefs boolForKey:key];

		if(enabled) {
			count++;
		}
	}

	return count;
}

void SHDWToggleHaptic(void) {
	// Fresh instance per event: toggle flips are rare, allocation cost is
	// irrelevant next to the impact itself.
	UIImpactFeedbackGenerator* generator = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
	[generator impactOccurred];
}
