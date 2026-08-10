#import "SHDWAppListController.h"
#import "SHDWHookLibs.h"
#import "SHDWPrefs.h"
#import "SHDWCapabilities.h"

#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>
#import <AltList/LSApplicationProxy+AltList.h>

@implementation SHDWAppListController {
	NSUserDefaults* prefs;

	NSMutableArray* hk_lib_values;
	NSMutableArray* hk_lib_titles;

	NSMutableArray* preset_values;
	NSMutableArray* preset_titles;
}

// YES while the app has no per-app override (App_Enabled absent or NO):
// the page collapses to "follow global" and the hook toggles are hidden.
- (BOOL)followGlobal {
	NSDictionary* appPrefs = [prefs dictionaryForKey:[self applicationID]];
	if(appPrefs && [appPrefs[@"App_Enabled"] boolValue]) {
		return NO;
	}

	return YES;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];

		// Title the page with the app's display name (AltList never sets the
		// pushed subcontroller's title); the plist title is the fallback.
		LSApplicationProxy* proxy = [LSApplicationProxy applicationProxyForIdentifier:[self applicationID]];
		if(proxy.atl_fastDisplayName.length > 0) {
			[self setTitle:proxy.atl_fastDisplayName];
		}

		if(![self followGlobal]) {
			[_specifiers addObjectsFromArray:[self loadSpecifiersFromPlistName:@"Hooks" target:self]];
		}

		// Tell the user why the hook rows are (not) shown. The group is found
		// by id (its display name is localized); the footer is written
		// already-localized, since specifier loading localizes plist strings.
		NSBundle* bundle = [NSBundle bundleForClass:[self class]];
		PSSpecifier* settingsGroup = [self specifierForID:@"AppSettingsGroup"];
		if(settingsGroup) {
			NSString* footer = [self followGlobal]
				? [bundle localizedStringForKey:@"APP_USES_GLOBAL" value:@"Following the global settings. Turn off to customize this app." table:@"App"]
				: [bundle localizedStringForKey:@"APP_SETTINGS_DESC" value:@"Adjust the bypass configuration for this application." table:@"App"];
			[settingsGroup setProperty:footer forKey:@"footerText"];
		}

		// The preset segment cell reads its options from specifier
		// properties; the titles are localized in code (Hooks table).
		PSSpecifier* presetSpecifier = [self specifierForID:@"BypassPreset"];
		if(presetSpecifier) {
			[presetSpecifier setProperty:preset_titles forKey:PSValidTitlesKey];
			[presetSpecifier setProperty:preset_values forKey:PSValidValuesKey];
		}

		// Same capability gating as the global Hooks page: per-app toggles
		// can't run a group the device's backends don't support either.
		// Gate instantly with cached state, then re-gate when the async
		// daemon refresh lands (never block the initial render on IPC).
		SHDWApplyHookGroupGating(_specifiers);
		[self refreshDaemonStateAndRegate];
	}

	return _specifiers;
}

- (void)refreshDaemonStateAndRegate {
	// Capture the state the current specifiers were rendered with. reloadSpecifiers
	// clears _specifiers and re-enters this method through the getter; the async
	// refresh's completion must not reload when the state is unchanged, or the
	// synchronous cache path recurses (reload → getter → refresh → reload…).
	SHDWDaemonState renderedState = SHDWQueryDaemonState();
	__weak typeof(self) weakSelf = self;

	SHDWRefreshDaemonStateAsync(^(SHDWDaemonState state) {
		typeof(self) self = weakSelf;
		if(!self) {
			return;
		}

		if(state == renderedState) {
			return;
		}

		SHDWApplyHookGroupGating(self->_specifiers);
		[self reloadSpecifiers];
	});
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"BypassPreset"]) {
		// Per-app effective values: the app's own dict falls back to the
		// global value per key (SHDWReadAppPref), so match on effective
		// values, not the raw per-app dict.
		if([self appPrefsMatchPreset:SHDWPresetStandard()]) {
			return @"standard";
		}

		if([self appPrefsMatchPreset:SHDWPresetMaximum()]) {
			return @"maximum";
		}

		return @"custom";
	}

	if([key isEqualToString:@"App_FollowGlobal"]) {
		return @([self followGlobal]);
	}

	return SHDWReadAppPref(prefs, [self applicationID], key);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"App_FollowGlobal"]) {
		// Following global = no per-app override; customizing flips the
		// per-app master switch on and reveals the hook rows.
		if([value boolValue]) {
			SHDWWriteAppPref(prefs, [self applicationID], @"App_Enabled", @(NO));
		} else {
			SHDWWriteAppPref(prefs, [self applicationID], @"App_Enabled", @(YES));
		}

		[self reloadSpecifiers];
		return;
	}

	if([key isEqualToString:@"BypassPreset"]) {
		// "custom" is a read-only status (no profile matches); selecting it
		// must not clobber the current settings. Reload so the segment
		// snaps back to the derived preset.
		if(![value isEqualToString:@"standard"] && ![value isEqualToString:@"maximum"]) {
			PSSpecifier* presetSpecifier = [self specifierForID:@"BypassPreset"];
			if(presetSpecifier) {
				[self reloadSpecifier:presetSpecifier];
			}
			return;
		}

		NSDictionary* preset = [value isEqualToString:@"maximum"] ? SHDWPresetMaximum() : SHDWPresetStandard();

		for(NSString* presetKey in preset) {
			SHDWWriteAppPref(prefs, [self applicationID], presetKey, preset[presetKey]);
		}

		// The framework only re-renders the edited cell; reload the hook
		// toggles so they reflect the applied preset without leaving the page.
		for(NSString* presetKey in preset) {
			PSSpecifier* toggleSpecifier = [self specifierForID:presetKey];
			if(toggleSpecifier) {
				[self reloadSpecifier:toggleSpecifier];
			}
		}

		return;
	}

	SHDWWriteAppPref(prefs, [self applicationID], key, value);

	// The preset row derives from the toggles; keep its displayed value in
	// sync when a toggle changes in place (Standard/Maximum → Custom).
	PSSpecifier* presetSpecifier = [self specifierForID:@"BypassPreset"];
	if(presetSpecifier) {
		[self reloadSpecifier:presetSpecifier];
	}
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	// Toggles flipped on a pushed page (Dangerous hooks) can change the
	// preset classification; refresh the preset row on return.
	PSSpecifier* presetSpecifier = [self specifierForID:@"BypassPreset"];
	if(presetSpecifier) {
		[self reloadSpecifier:presetSpecifier];
	}
}

// Effective-value preset match: every preset key must equal the per-app
// effective value (app override, else global fallback).
- (BOOL)appPrefsMatchPreset:(NSDictionary *)preset {
	for(NSString* key in preset) {
		if(![SHDWReadAppPref(prefs, [self applicationID], key) isEqual:preset[key]]) {
			return NO;
		}
	}

	return YES;
}

- (NSArray *)getValues:(PSSpecifier *)specifier {
	return [hk_lib_values copy];
}

- (NSArray *)getTitles:(PSSpecifier *)specifier {
	return [hk_lib_titles copy];
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];

		hk_lib_values = [NSMutableArray new];
		hk_lib_titles = [NSMutableArray new];

		[hk_lib_values addObject:@"auto"];
		[hk_lib_titles addObject:[[NSBundle bundleForClass:[self class]] localizedStringForKey:@"AUTOMATIC" value:@"Automatic" table:@"Hooks"]];

        for(NSDictionary* hooklib_info in SHDWAvailableHookLibs()) {
			[hk_lib_values addObject:hooklib_info[@"id"]];
			[hk_lib_titles addObject:hooklib_info[@"name"]];
        }

		NSBundle* bundle = [NSBundle bundleForClass:[self class]];
		preset_values = [NSMutableArray new];
		preset_titles = [NSMutableArray new];

		[preset_values addObject:@"standard"];
		[preset_titles addObject:[bundle localizedStringForKey:@"PRESET_STANDARD" value:@"Standard" table:@"Hooks"]];

		[preset_values addObject:@"maximum"];
		[preset_titles addObject:[bundle localizedStringForKey:@"PRESET_MAXIMUM" value:@"Maximum" table:@"Hooks"]];

		[preset_values addObject:@"custom"];
		[preset_titles addObject:[bundle localizedStringForKey:@"PRESET_CUSTOM" value:@"Custom" table:@"Hooks"]];
	}

	return self;
}
@end
