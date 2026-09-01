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
// kUTTypePropertyList keeps the document picker compatible with iOS 9.
#import <CoreServices/CoreServices.h>

// Only activation state and detector evidence are user-owned settings. Legacy
// activation keys remain importable so old backups keep their behavior.
static NSSet* SHDWAllowedKeys(void) {
	static NSSet* keys = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		keys = [NSSet setWithArray:@[
			SHDWAppEnabledID, SHDWAppDisabledID, SHDWGlobalEnabledID,
			SHDWSingleToggleMigrationID, @"DetectorLog"
		]];
	});

	return keys;
}

// Validate one value against its key's expected class: activation switches are
// NSNumber, DetectorLog is an NSArray of NSString,
// and any other top-level key must be a per-app override dict (bundle ID)
// whose inner keys follow the same rules. Returns the value (per-app dicts
// sanitized down to known inner keys) or nil to drop it — a hand-edited
// backup must never write wrongly-typed values that crash ShadowCore later.
static id SHDWSanitizeValue(NSString* key, id value) {
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

	if([key isEqualToString:@"ApplicationsSummary"]) {
		NSInteger excluded = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if([value isKindOfClass:[NSDictionary class]] &&
			   ([[value objectForKey:SHDWAppDisabledID] boolValue] ||
			    ([value objectForKey:SHDWAppEnabledID] && ![[value objectForKey:SHDWAppEnabledID] boolValue]))) {
				excluded++;
			}
		}

		// Global_Enabled makes every eligible app active, so the summary is
		// trivial — unless some apps are explicitly excluded, which "all apps
		// enabled" would misreport.
		if([prefs boolForKey:@"Global_Enabled"]) {
			if(excluded == 0) {
				return [self localized:@"APPS_ALL_ENABLED" fallback:@"All apps enabled"];
			}

			return [NSString stringWithFormat:[self localized:@"APPS_EXCLUDED_FMT" fallback:@"All apps enabled · %ld excluded"], (long)excluded];
		}

		NSInteger count = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if([value isKindOfClass:[NSDictionary class]] && [[value objectForKey:SHDWAppEnabledID] boolValue]
				&& ![[value objectForKey:SHDWAppDisabledID] boolValue]) {
				count++;
			}
		}

		return [NSString stringWithFormat:[self localized:@"APPS_ENABLED_FMT" fallback:@"%ld enabled"], (long)count];
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

	// The summary derives from switches changed on pushed app pages.
	for(NSString* specID in @[ @"ApplicationsSummary" ]) {
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
	activePicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[(NSString *)kUTTypePropertyList] inMode:UIDocumentPickerModeImport];
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

	// Normalize legacy follow-global state before making App_Enabled explicit.
	BOOL legacyGlobalEnabled = [sanitized[SHDWGlobalEnabledID] boolValue];
	BOOL singleToggleMigrated = [sanitized[SHDWSingleToggleMigrationID] boolValue];
	for(NSString* key in sanitized.allKeys) {
		id value = sanitized[key];
		if([value isKindOfClass:[NSDictionary class]]) {
			NSMutableDictionary* app = [value mutableCopy];
			app[SHDWAppEnabledID] = @(SHDWApplicationEnabled(value, legacyGlobalEnabled,
				singleToggleMigrated, NO));
			[app removeObjectForKey:SHDWAppDisabledID];
			sanitized[key] = [app copy];
		}
	}
	[sanitized removeObjectForKey:SHDWAppDisabledID];
	sanitized[SHDWSingleToggleMigrationID] = @YES;

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

		// Refresh the derived app summary without a respring.
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
