#import "SHDWRootListController.h"
#import "SHDWPrefs.h"

// The document picker keeps an iOS 12-compatible path; its UTI APIs are
// deprecated as of iOS 15, which -Werror turns into a hard error at the
// roothide/rootless build target (15.0).
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import <Shadow/Core+Utilities.h>
#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>
#import <Shadow/JBPath.h>

#import <UIKit/UIKit.h>
// Both UTIs are needed: kUTTypePropertyList (CoreServices) for the iOS 12
// fallback, UTTypePropertyList (UniformTypeIdentifiers) on iOS 14+.
#import <CoreServices/CoreServices.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

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

// Canonical Shadow preference keys (single source: the framework defaults,
// plus App_Enabled and the detector log). Per-app override dicts (bundle-ID
// keys) are recognized by their dictionary value, not listed here.
static NSSet* SHDWAllowedKeys(void) {
	static NSSet* keys = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		NSMutableSet* mutableKeys = [NSMutableSet setWithArray:[SHDWDefaultHookSettings() allKeys]];
		[mutableKeys addObject:SHDWAppEnabledID];
		[mutableKeys addObject:@"DetectorLog"];
		keys = [mutableKeys copy];
	});

	return keys;
}

// Validate one value against its key's expected class: switches
// (Global_Enabled, App_Enabled, Hook_*, VnodeHiding, MemoryLevelHiding) are
// NSNumber, HK_Library is NSString, DetectorLog is an NSArray of NSString,
// and any other top-level key must be a per-app override dict (bundle ID)
// whose inner keys follow the same rules. Returns the value (per-app dicts
// sanitized down to known inner keys) or nil to drop it — a hand-edited
// backup must never write wrongly-typed values that crash ShadowCore later.
static id SHDWSanitizeValue(NSString* key, id value) {
	if([key isEqualToString:SHDWHookLibraryID]) {
		return [value isKindOfClass:[NSString class]] ? value : nil;
	}

	if([key isEqualToString:@"DetectorLog"]) {
		if(![value isKindOfClass:[NSArray class]]) {
			return nil;
		}

		for(id entry in value) {
			if(![entry isKindOfClass:[NSString class]]) {
				return nil;
			}
		}

		return value;
	}

	if([SHDWAllowedKeys() containsObject:key]) {
		return [value isKindOfClass:[NSNumber class]] ? value : nil;
	}

	// Unknown top-level key: keep it only as a per-app override dict.
	if([value isKindOfClass:[NSDictionary class]]) {
		NSMutableDictionary* sanitized = [NSMutableDictionary new];

		for(NSString* innerKey in value) {
			id innerValue = SHDWSanitizeValue(innerKey, value[innerKey]);
			if(innerValue) {
				sanitized[innerKey] = innerValue;
			}
		}

		return sanitized.count > 0 ? sanitized : nil;
	}

	return nil;
}

// Shadow's own preferences only: the allowlisted keys plus per-app override
// dicts, validated through SHDWSanitizeValue. Never the raw
// dictionaryRepresentation — that composite mixes in registered-default,
// managed and argument domains, leaking unrelated keys into backups.
static NSDictionary* SHDWExportablePrefs(NSUserDefaults* prefs) {
	NSMutableDictionary* export = [NSMutableDictionary new];
	NSDictionary* all = [prefs dictionaryRepresentation];

	for(NSString* key in all) {
		id value = SHDWSanitizeValue(key, all[key]);
		if(value) {
			export[key] = value;
		}
	}

	return export;
}

@interface SHDWRootListController () <UIDocumentPickerDelegate>
@end

@implementation SHDWRootListController {
	NSUserDefaults* prefs;
	UIDocumentPickerViewController* activePicker;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

- (NSString *)localized:(NSString *)key fallback:(NSString *)fallback {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:fallback table:@"Root"];
}

- (void)presentAlert:(NSString *)title message:(NSString *)message {
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_OK" fallback:@"OK"] style:UIAlertActionStyleDefault handler:nil]];
	[self presentViewController:alert animated:YES completion:nil];
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	NSString* key = [specifier identifier];

	if([key isEqualToString:@"BypassPresetSummary"]) {
		// Mirror the global bypass page's preset derivation.
		NSString* presetID = @"custom";
		if(PrefsMatchPreset(prefs, SHDWPresetStandard())) {
			presetID = @"standard";
		} else if(PrefsMatchPreset(prefs, SHDWPresetMaximum())) {
			presetID = @"maximum";
		}

		NSString* presetKey = [NSString stringWithFormat:@"PRESET_%@", [presetID uppercaseString]];
		return [[NSBundle bundleForClass:[self class]] localizedStringForKey:presetKey value:presetID table:@"Hooks"];
	}

	if([key isEqualToString:@"ApplicationsSummary"]) {
		// Global_Enabled makes every eligible app active, so the summary is
		// trivial; otherwise count the per-app customizations.
		if([prefs boolForKey:@"Global_Enabled"]) {
			return [self localized:@"APPS_ALL_ENABLED" fallback:@"All apps enabled"];
		}

		NSInteger count = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if([value isKindOfClass:[NSDictionary class]] && [[value objectForKey:@"App_Enabled"] boolValue]) {
				count++;
			}
		}

		return [NSString stringWithFormat:[self localized:@"APPS_CUSTOMIZED_FMT" fallback:@"%ld customized"], (long)count];
	}

	return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	SHDWToggleHaptic();
	[prefs setObject:value forKey:[specifier identifier]];
	[prefs synchronize];
}

- (void)viewWillAppear:(BOOL)animated {
	[super viewWillAppear:animated];

	// The summary rows derive from settings that can change on pushed pages
	// (preset, per-app overrides); refresh them on every return.
	for(NSString* specID in @[ @"BypassPresetSummary", @"ApplicationsSummary" ]) {
		PSSpecifier* summary = [self specifierForID:specID];
		if(summary) {
			[self reloadSpecifier:summary];
		}
	}
}

- (void)respring:(id)sender {
	// Prefer sbreload (clean relaunch); fall back to a hard killall -9,
	// then to an alert if neither tool can be spawned.
	BOOL spawned = NO;

	if([[NSFileManager defaultManager] fileExistsAtPath:JBPath(@"/usr/bin/sbreload")]) {
		pid_t pid;
		const char *args[] = {"sbreload", NULL, NULL, NULL};
		spawned = posix_spawn(&pid, [JBPath(@"/usr/bin/sbreload") fileSystemRepresentation], NULL, NULL, (char *const *)args, NULL) == 0;
	}

	if(!spawned) {
		pid_t pid;
		const char *args[] = {"killall", "-9", "SpringBoard", NULL};
		spawned = posix_spawn(&pid, [JBPath(@"/usr/bin/killall") fileSystemRepresentation], NULL, NULL, (char *const *)args, NULL) == 0;
	}

	if(!spawned) {
		NSLog(@"Shadow: respring failed, neither sbreload nor killall could be spawned");
		[self presentAlert:[self localized:@"RESPRING_FAILED_TITLE" fallback:@"Respring failed"] message:[self localized:@"RESPRING_FAILED_MSG" fallback:@"Neither sbreload nor killall could be launched. Changes take effect after SpringBoard restarts."]];
	}
}

- (void)reset:(id)sender {
	NSDictionary* prefs_dict = [prefs dictionaryRepresentation];
    for(id key in prefs_dict) {
		[prefs removeObjectForKey:key];
    }

    [prefs synchronize];
	
	[self respring:sender];
}

- (void)exportSettings:(id)sender {
	NSError* error = nil;
	NSData* data = [NSPropertyListSerialization dataWithPropertyList:SHDWExportablePrefs(prefs) format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];

	if(!data) {
		NSLog(@"Shadow: export serialization failed: %@", error);
		[self presentAlert:[self localized:@"EXPORT_FAILED_TITLE" fallback:@"Export failed"] message:[self localized:@"EXPORT_FAILED_MSG" fallback:@"The settings could not be written to a file."]];
		return;
	}

	NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ShadowSettings.plist"];
	if(![data writeToFile:path atomically:YES]) {
		NSLog(@"Shadow: export write failed: %@", path);
		[self presentAlert:[self localized:@"EXPORT_FAILED_TITLE" fallback:@"Export failed"] message:[self localized:@"EXPORT_FAILED_MSG" fallback:@"The settings could not be written to a file."]];
		return;
	}

	UIActivityViewController* avc = [[UIActivityViewController alloc] initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
	avc.popoverPresentationController.sourceView = self.view;
	avc.popoverPresentationController.sourceRect = self.view.bounds;

	// The share sheet owns the temp file; remove it when it's done (the
	// handler runs on dismiss, including cancel).
	avc.completionWithItemsHandler = ^(NSString* activityType, BOOL completed, NSArray* returnedItems, NSError* activityError) {
		[[NSFileManager defaultManager] removeItemAtPath:path error:nil];
	};

	[self presentViewController:avc animated:YES completion:nil];
}

- (void)importSettings:(id)sender {
	// Modern initializer on iOS 14+; the old one stays for the iOS 12
	// baseline (the project's minimum).
	if(@available(iOS 14.0, *)) {
		activePicker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypePropertyList] asCopy:YES];
	} else {
		activePicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[(NSString *)kUTTypePropertyList] inMode:UIDocumentPickerModeImport];
	}
	activePicker.delegate = self;
	[self presentViewController:activePicker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
	activePicker = nil;

	if(urls.count == 0) {
		return;
	}

	NSData* data = [NSData dataWithContentsOfURL:urls[0]];
	NSDictionary* imported = nil;

	// Cap the file: a real backup is a few KB of toggles; anything larger is
	// not a Shadow settings plist.
	if(data && data.length <= 1024 * 1024) {
		id plist = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];

		if([plist isKindOfClass:[NSDictionary class]]) {
			imported = plist;
		}
	}

	// Validate against the allowlist and drop foreign keys or wrongly-typed
	// values before anything touches live preferences.
	NSMutableDictionary* sanitized = [NSMutableDictionary new];
	for(NSString* key in imported) {
		id value = SHDWSanitizeValue(key, imported[key]);
		if(value) {
			sanitized[key] = value;
		}
	}

	if(!imported || sanitized.count == 0) {
		[self presentAlert:[self localized:@"IMPORT_BAD_FILE" fallback:@"The selected file is not a valid Shadow settings backup."] message:nil];
		return;
	}

	UIAlertController* confirm = [UIAlertController alertControllerWithTitle:[self localized:@"IMPORT_CONFIRM_TITLE" fallback:@"Import Settings?"] message:[self localized:@"IMPORT_CONFIRM_MSG" fallback:@"This replaces all current settings with the selected file."] preferredStyle:UIAlertControllerStyleAlert];

	[confirm addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_CANCEL" fallback:@"Cancel"] style:UIAlertActionStyleCancel handler:nil]];
	[confirm addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_CONFIRM" fallback:@"Import"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
		NSDictionary* prefs_dict = [prefs dictionaryRepresentation];
		for(id key in prefs_dict) {
			[prefs removeObjectForKey:key];
		}

		for(NSString* key in sanitized) {
			[prefs setObject:sanitized[key] forKey:key];
		}

		[prefs synchronize];

		// Refresh the pane so the imported state (Global_Enabled switch,
		// derived summary rows) shows without a respring.
		[self reloadSpecifiers];

		UIAlertController* applied = [UIAlertController alertControllerWithTitle:[self localized:@"IMPORT_APPLIED" fallback:@"Settings imported. Respring to apply."] message:nil preferredStyle:UIAlertControllerStyleAlert];
		[applied addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_OK" fallback:@"OK"] style:UIAlertActionStyleCancel handler:nil]];
		[applied addAction:[UIAlertAction actionWithTitle:[self localized:@"RESPRING" fallback:@"Respring"] style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
			[self respring:nil];
		}]];
		[self presentViewController:applied animated:YES completion:nil];
	}]];

	[self presentViewController:confirm animated:YES completion:nil];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
	activePicker = nil;
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
