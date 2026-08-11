#import "SHDWHooksListController.h"
#import "SHDWHookLibs.h"
#import "SHDWPrefs.h"
#import "SHDWCapabilities.h"

#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>

// The theos PSSpecifier header omits the values/titles accessors the
// framework uses; declare them so PSSegmentCell can read its options.
@interface PSSpecifier (ShadowSegments)
- (void)setValues:(NSArray *)values titles:(NSArray *)titles;
@end

@implementation SHDWHooksListController {
	NSUserDefaults* prefs;

	NSMutableArray* hk_lib_values;
	NSMutableArray* hk_lib_titles;

	NSMutableArray* preset_values;
	NSMutableArray* preset_titles;
}

// Preset profiles: batch values for every hook toggle. "standard" mirrors the
// shipped defaults; "maximum" enables everything including dangerous hooks.
// Canonical values come from Shadow/HookConfiguration.h (SHDWPresetStandard /
// SHDWPresetMaximum) — the metadata is the single source of truth. The stale
// Hook_FakeMac key is absent from both, so a stored legacy value is simply
// ignored by PrefsMatchPreset.

static BOOL PrefsMatchPreset(NSUserDefaults* prefs, NSDictionary* preset) {
	for(NSString* key in preset) {
		if([SHDWReadAppPref(prefs, nil, key) boolValue] != [preset[key] boolValue]) {
			return NO;
		}
	}

	return YES;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Hooks" target:self];
		[self setTitle:[[NSBundle bundleForClass:[self class]] localizedStringForKey:@"BYPASS_SETTINGS" value:@"Bypass Settings" table:@"Root"]];

		// The preset segment cell reads its options from the specifier's
		// values/titles (the plist loader converts validValues/validTitles,
		// but we set them in code, so go through the cell-facing API);
		// the titles are localized in code (Hooks table).
		PSSpecifier* presetSpecifier = [self specifierForID:@"BypassPreset"];
		if(presetSpecifier) {
			[presetSpecifier setValues:preset_values titles:preset_titles];
			[presetSpecifier setProperty:preset_titles forKey:PSValidTitlesKey];
			[presetSpecifier setProperty:preset_values forKey:PSValidValuesKey];
		}

		// Disable hook groups whose backend capability is missing on this
		// device (message/function/inline), with a footer note per group.
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
	if([[specifier identifier] isEqualToString:@"BypassStatus"]) {
		// "N hooks active · <preset>": count the enabled hook toggles (the
		// canonical preset key set), derive the preset the same way the
		// segment row does.
		NSInteger count = SHDWCountEnabledHooks(prefs, nil);

		NSString* presetID = @"custom";
		if(PrefsMatchPreset(prefs, SHDWPresetStandard())) {
			presetID = @"standard";
		} else if(PrefsMatchPreset(prefs, SHDWPresetMaximum())) {
			presetID = @"maximum";
		}

		NSString* presetKey = [NSString stringWithFormat:@"PRESET_%@", [presetID uppercaseString]];
		NSString* presetTitle = [[NSBundle bundleForClass:[self class]] localizedStringForKey:presetKey value:presetID table:@"Hooks"];

		NSString* statusKey = (count == 1) ? @"STATUS_FMT_SINGULAR" : @"STATUS_FMT";
		return [NSString stringWithFormat:[[NSBundle bundleForClass:[self class]] localizedStringForKey:statusKey value:@"%ld hooks active · %@" table:@"Hooks"], (long)count, presetTitle];
	}

	if([[specifier identifier] isEqualToString:@"BypassPreset"]) {
		if(PrefsMatchPreset(prefs, SHDWPresetStandard())) {
			return @"standard";
		}

		if(PrefsMatchPreset(prefs, SHDWPresetMaximum())) {
			return @"maximum";
		}

		return @"custom";
	}

	return SHDWReadAppPref(prefs, nil, [specifier identifier]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();

	if([[specifier identifier] isEqualToString:@"BypassPreset"]) {
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

		for(NSString* key in preset) {
			SHDWWriteAppPref(prefs, nil, key, preset[key]);
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

	SHDWWriteAppPref(prefs, nil, [specifier identifier], value);

	// The preset row derives from the toggles; keep its displayed value in
	// sync when a toggle changes in place (Standard/Maximum → Custom).
	PSSpecifier* presetSpecifier = [self specifierForID:@"BypassPreset"];
	if(presetSpecifier) {
		[self reloadSpecifier:presetSpecifier];
	}
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	// Toggles flipped on a pushed page (Individual/Dangerous hooks) can
	// change the preset classification and the status line; refresh both.
	for(NSString* specID in @[ @"BypassPreset", @"BypassStatus" ]) {
		PSSpecifier* specifier = [self specifierForID:specID];
		if(specifier) {
			[self reloadSpecifier:specifier];
		}
	}
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
