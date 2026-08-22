#import "SHDWAppListController.h"
#import "SHDWPrefs.h"
#import "SHDWCapabilities.h"

#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>
#import <AltList/LSApplicationProxy+AltList.h>

// The theos PSSpecifier header omits the values/titles accessors the
// framework uses; declare them so PSSegmentCell can read its options.
@interface PSSpecifier (ShadowSegments)
- (void)setValues:(NSArray *)values titles:(NSArray *)titles;
@end

@implementation SHDWAppListController {
	NSUserDefaults* prefs;

	// Hook rows loaded once and kept across reloads; the Follow Global
	// toggle animates them in/out (native row insert/delete) instead of a
	// full table reload.
	NSArray* hookSpecifiers;

	// Same reason as hookSpecifiers: the kill switch removes this row from the
	// table, so specifierForID: can no longer find it to put it back.
	PSSpecifier* followGlobalSpecifier;

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

// YES when the user has excluded this app from Shadow entirely. Independent of
// followGlobal — the kill switch overrides the global toggle, so an excluded
// app shows no configuration at all.
- (BOOL)appDisabled {
	NSDictionary* appPrefs = [prefs dictionaryForKey:[self applicationID]];
	return appPrefs && [appPrefs[SHDWAppDisabledID] boolValue];
}

// Rows that only make sense while Shadow is active in this app: the Follow
// Global switch and, when customizing, every hook row behind it.
- (NSArray *)configurationSpecifiers {
	NSMutableArray* specs = [NSMutableArray new];

	if(followGlobalSpecifier) {
		[specs addObject:followGlobalSpecifier];
	}

	if(![self followGlobal]) {
		[specs addObjectsFromArray:hookSpecifiers];
	}

	return specs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"App" target:self];

		// Load the hook rows once (kept across reloads so the Follow Global
		// toggle can animate them in/out), gated the same way the global
		// Hooks page gates them.
		hookSpecifiers = [self loadSpecifiersFromPlistName:@"Hooks" target:self];
		SHDWApplyHookGroupGating(hookSpecifiers);

		followGlobalSpecifier = [self specifierForID:@"App_FollowGlobal"];

		// Title the page with the app's display name (AltList never sets the
		// pushed subcontroller's title). After both plist loads, so neither
		// re-applies its own plist title over it.
		LSApplicationProxy* proxy = [LSApplicationProxy applicationProxyForIdentifier:[self applicationID]];
		if(proxy.atl_fastDisplayName.length > 0) {
			[self setTitle:proxy.atl_fastDisplayName];
		}

		if([self appDisabled]) {
			// Excluded app: nothing below the kill switch applies.
			[self removeSpecifier:followGlobalSpecifier animated:NO];
		} else if(![self followGlobal]) {
			// Insert behind the Follow Global row — the same anchor the live
			// flip uses, so initial and on-the-fly customization order alike.
			PSSpecifier* anchor = [self specifierForID:@"App_FollowGlobal"];
			for(PSSpecifier* spec in hookSpecifiers) {
				[self insertSpecifier:spec afterSpecifier:anchor animated:NO];
				anchor = spec;
			}
		}

		[self updateSettingsGroupFooter];

		// The preset segment cell reads its options from the specifier's
		// values/titles (the plist loader converts validValues/validTitles,
		// but we set them in code, so go through the cell-facing API);
		// the titles are localized in code (Hooks table). Configure the
		// specifier inside the loaded rows, so the segment arrives
		// configured on every insertion path — the initial custom load and
		// the live Follow Global flip (which inserts these specifiers as-is).
		for(PSSpecifier* spec in hookSpecifiers) {
			if([[spec identifier] isEqualToString:@"BypassPreset"]) {
				[spec setValues:preset_values titles:preset_titles];
				[spec setProperty:preset_titles forKey:PSValidTitlesKey];
				[spec setProperty:preset_values forKey:PSValidValuesKey];
				break;
			}
		}

		// Same capability gating as the global Hooks page: per-app toggles
		// can't run a group the device's backends don't support either.
		// Gate instantly with cached state, then re-gate when the async
	}

	return _specifiers;
}

// Group footer explaining why the hook rows are (not) shown. The group is
// found by id (its display name is localized); the footer is written
// already-localized, since specifier loading localizes plist strings.
- (void)updateSettingsGroupFooter {
	NSBundle* bundle = [NSBundle bundleForClass:[self class]];
	PSSpecifier* settingsGroup = [self specifierForID:@"AppSettingsGroup"];
	if(settingsGroup) {
		NSString* footer;

		if([self appDisabled]) {
			footer = [bundle localizedStringForKey:@"APP_IS_DISABLED" value:@"Shadow is not loaded into this application." table:@"App"];
		} else if([self followGlobal]) {
			footer = [bundle localizedStringForKey:@"APP_USES_GLOBAL" value:@"Following the global settings. Turn off to customize this app." table:@"App"];
		} else {
			footer = [bundle localizedStringForKey:@"APP_SETTINGS_DESC" value:@"Adjust the bypass configuration for this application." table:@"App"];
		}

		[settingsGroup setProperty:footer forKey:@"footerText"];
	}
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"BypassStatus"]) {
		// "N hooks active · <preset>": count the effective per-app hook
		// toggles (app override, else global fallback), derive the preset
		// the same way the segment row does.
		NSInteger count = SHDWCountEnabledHooks(prefs, [self applicationID]);

		NSString* presetID = @"custom";
		if([self appPrefsMatchPreset:SHDWPresetStandard()]) {
			presetID = @"standard";
		} else if([self appPrefsMatchPreset:SHDWPresetMaximum()]) {
			presetID = @"maximum";
		}

		NSString* presetKey = [NSString stringWithFormat:@"PRESET_%@", [presetID uppercaseString]];
		NSString* presetTitle = [[NSBundle bundleForClass:[self class]] localizedStringForKey:presetKey value:presetID table:@"Hooks"];

		NSString* statusKey = (count == 1) ? @"STATUS_FMT_SINGULAR" : @"STATUS_FMT";
		return [NSString stringWithFormat:[[NSBundle bundleForClass:[self class]] localizedStringForKey:statusKey value:@"%ld hooks active · %@" table:@"Hooks"], (long)count, presetTitle];
	}

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

	// Read the app's own dict, never the global fallback: exclusion is per-app
	// by definition and there is no global App_Disabled.
	if([key isEqualToString:SHDWAppDisabledID]) {
		return @([self appDisabled]);
	}

	return SHDWReadAppPref(prefs, [self applicationID], key);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	NSString* key = [specifier identifier];

	if([key isEqualToString:SHDWAppDisabledID]) {
		// Excluding the app hides everything below the switch; re-including it
		// restores whatever the app's own configuration was. Same animated
		// insert/remove as the Follow Global flip below.
		NSArray* rows = [self configurationSpecifiers];

		SHDWWriteAppPref(prefs, [self applicationID], SHDWAppDisabledID, @([value boolValue]));

		if([value boolValue]) {
			for(PSSpecifier* spec in [rows reverseObjectEnumerator]) {
				[self removeSpecifier:spec animated:YES];
			}
		} else {
			PSSpecifier* anchor = [self specifierForID:SHDWAppDisabledID];
			for(PSSpecifier* spec in rows) {
				[self insertSpecifier:spec afterSpecifier:anchor animated:YES];
				anchor = spec;
			}
		}

		[self updateSettingsGroupFooter];
		PSSpecifier* settingsGroup = [self specifierForID:@"AppSettingsGroup"];
		if(settingsGroup) {
			[self reloadSpecifier:settingsGroup];
		}
		return;
	}

	if([key isEqualToString:@"App_FollowGlobal"]) {
		// Following global = no per-app override; customizing flips the
		// per-app master switch on and reveals the hook rows. Rows animate
		// in/out (native insert/delete) like Settings' own conditional rows,
		// instead of a full table reload.
		if([value boolValue]) {
			SHDWWriteAppPref(prefs, [self applicationID], @"App_Enabled", @(NO));
			for(PSSpecifier* spec in [hookSpecifiers reverseObjectEnumerator]) {
				[self removeSpecifier:spec animated:YES];
			}
		} else {
			SHDWWriteAppPref(prefs, [self applicationID], @"App_Enabled", @(YES));
			PSSpecifier* anchor = [self specifierForID:@"App_FollowGlobal"];
			for(PSSpecifier* spec in hookSpecifiers) {
				[self insertSpecifier:spec afterSpecifier:anchor animated:YES];
				anchor = spec;
			}
		}

		// The group's footer explains the current state; refresh it to match.
		[self updateSettingsGroupFooter];
		PSSpecifier* settingsGroup = [self specifierForID:@"AppSettingsGroup"];
		if(settingsGroup) {
			[self reloadSpecifier:settingsGroup];
		}
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

		// Batch write: flush explicitly (per-write synchronize was dropped;
		// the batch must be durable before returning).
		[prefs synchronize];

		// The hook toggles live on pushed pages, not this controller (their
		// specifierForID: here is nil), so there is nothing to reload — but
		// the status row derives from the applied preset and must refresh.
		PSSpecifier* status = [self specifierForID:@"BypassStatus"];
		if(status) {
			[self reloadSpecifier:status];
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
	// preset classification and the status line; refresh both on return.
	for(NSString* specID in @[ @"BypassPreset", @"BypassStatus" ]) {
		PSSpecifier* specifier = [self specifierForID:specID];
		if(specifier) {
			[self reloadSpecifier:specifier];
		}
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

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];

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
