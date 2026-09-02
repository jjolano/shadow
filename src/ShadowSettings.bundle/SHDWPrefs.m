#import "SHDWPrefs.h"

#import <UIKit/UIKit.h>
#import <Shadow/HookConfiguration.h>

BOOL SHDWAppEnabled(NSUserDefaults *prefs, NSString *appID) {
	NSDictionary* appPrefs = [prefs dictionaryForKey:appID];
	return SHDWApplicationEnabled(appPrefs,
		[prefs boolForKey:SHDWGlobalEnabledID],
		[prefs boolForKey:SHDWSingleToggleMigrationID], NO);
}

void SHDWWriteAppEnabled(NSUserDefaults *prefs, NSString *appID, BOOL enabled) {
	NSMutableDictionary* appPrefs = [[prefs dictionaryForKey:appID] mutableCopy] ?: [NSMutableDictionary new];
	appPrefs[SHDWAppEnabledID] = @(enabled);
	[appPrefs removeObjectForKey:SHDWAppDisabledID];
	[prefs setBool:YES forKey:SHDWSingleToggleMigrationID];
	[prefs setObject:[appPrefs copy] forKey:appID];
}

BOOL SHDWAppFollowsGlobal(NSUserDefaults *prefs, NSString *appID) {
	NSDictionary* appPrefs = [prefs dictionaryForKey:appID];
	// No explicit activation override → the runtime uses the global toggle.
	return appPrefs[SHDWAppEnabledID] == nil;
}

void SHDWClearAppEnabled(NSUserDefaults *prefs, NSString *appID) {
	NSMutableDictionary* appPrefs = [[prefs dictionaryForKey:appID] mutableCopy];
	if(!appPrefs) {
		return;
	}
	[appPrefs removeObjectForKey:SHDWAppEnabledID];
	[appPrefs removeObjectForKey:SHDWAppDisabledID];
	[prefs setBool:YES forKey:SHDWSingleToggleMigrationID];
	// Drop the app's dictionary entirely once it holds no overrides, so a
	// "follow global" app leaves no residue in the backing plist.
	if(appPrefs.count == 0) {
		[prefs removeObjectForKey:appID];
	} else {
		[prefs setObject:[appPrefs copy] forKey:appID];
	}
}

void SHDWToggleHaptic(void) {
	// Fresh instance per event: toggle flips are rare, allocation cost is
	// irrelevant next to the impact itself.
	UIImpactFeedbackGenerator* generator = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
	[generator impactOccurred];
}
