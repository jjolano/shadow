#import "SHDWHooksListController.h"
#import "SHDWHookLibs.h"
#import "SHDWPrefs.h"
#import "SHDWCapabilities.h"

#import <Shadow/Settings.h>

@implementation SHDWHooksListController {
	NSUserDefaults* prefs;

	NSMutableArray* hk_lib_values;
	NSMutableArray* hk_lib_titles;

	NSMutableArray* preset_values;
	NSMutableArray* preset_titles;
}

// Preset profiles: batch values for every hook toggle. "standard" mirrors the
// shipped defaults; "maximum" enables everything including dangerous hooks.
static NSDictionary* PresetStandard() {
	return @{
		@"Hook_Filesystem" : @(YES),
		@"Hook_URLScheme" : @(YES),
		@"Hook_EnvVars" : @(YES),
		@"Hook_DeviceCheck" : @(YES),
		@"Hook_Foundation" : @(NO),
		@"Hook_MachBootstrap" : @(NO),
		@"Hook_IOKit" : @(NO),
		@"Hook_LowLevelC" : @(YES),
		@"Hook_AntiDebugging" : @(NO),
		@"Hook_DynamicLibrariesExtra" : @(NO),
		@"Hook_FakeMac" : @(NO),
		@"Hook_Syscall" : @(NO),
		@"Hook_Sandbox" : @(NO),
		@"Hook_Memory" : @(NO),
		@"Hook_HideApps" : @(YES),
		@"VnodeHiding" : @(NO)
	};
}

static NSDictionary* PresetMaximum() {
	return @{
		@"Hook_Filesystem" : @(YES),
		@"Hook_URLScheme" : @(YES),
		@"Hook_EnvVars" : @(YES),
		@"Hook_DeviceCheck" : @(YES),
		@"Hook_Foundation" : @(YES),
		@"Hook_MachBootstrap" : @(YES),
		@"Hook_IOKit" : @(YES),
		@"Hook_LowLevelC" : @(YES),
		@"Hook_AntiDebugging" : @(YES),
		@"Hook_DynamicLibrariesExtra" : @(YES),
		@"Hook_FakeMac" : @(YES),
		@"Hook_Syscall" : @(YES),
		@"Hook_Sandbox" : @(YES),
		@"Hook_Memory" : @(YES),
		@"Hook_HideApps" : @(YES),
		@"VnodeHiding" : @(YES)
	};
}

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

		// Disable hook groups whose backend capability is missing on this
		// device (message/function/inline), with a footer note per group.
		SHDWApplyHookGroupGating(_specifiers);
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	if([[specifier identifier] isEqualToString:@"BypassPreset"]) {
		if(PrefsMatchPreset(prefs, PresetStandard())) {
			return @"standard";
		}

		if(PrefsMatchPreset(prefs, PresetMaximum())) {
			return @"maximum";
		}

		return @"custom";
	}

	return SHDWReadAppPref(prefs, nil, [specifier identifier]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	if([[specifier identifier] isEqualToString:@"BypassPreset"]) {
		// "custom" is a read-only status (no profile matches); selecting it
		// must not clobber the current settings.
		if(![value isEqualToString:@"standard"] && ![value isEqualToString:@"maximum"]) {
			return;
		}

		NSDictionary* preset = [value isEqualToString:@"maximum"] ? PresetMaximum() : PresetStandard();

		for(NSString* key in preset) {
			SHDWWriteAppPref(prefs, nil, key, preset[key]);
		}

		return;
	}

	SHDWWriteAppPref(prefs, nil, [specifier identifier], value);
}

- (NSArray *)getPresetValues:(PSSpecifier *)specifier {
	return [preset_values copy];
}

- (NSArray *)getPresetTitles:(PSSpecifier *)specifier {
	return [preset_titles copy];
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
