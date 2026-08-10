#import "SHDWRootListController.h"
#import "SHDWPrefs.h"

#import <Shadow/Core+Utilities.h>
#import <Shadow/Settings.h>
#import <Shadow/HookConfiguration.h>
#import <Shadow/JBPath.h>

#import <UIKit/UIKit.h>
// MobileCoreServices re-exports CoreServices on modern SDKs; import the
// framework that actually declares kUTType* (identical symbol at runtime).
#import <CoreServices/CoreServices.h>

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
		NSInteger count = 0;
		for(id value in [prefs dictionaryRepresentation].allValues) {
			if([value isKindOfClass:[NSDictionary class]] && [[value objectForKey:@"App_Enabled"] boolValue]) {
				count++;
			}
		}

		return [NSString stringWithFormat:[self localized:@"APPS_ENABLED_FMT" fallback:@"%ld enabled"], (long)count];
	}

	return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	[prefs setObject:value forKey:[specifier identifier]];
	[prefs synchronize];
}

- (void)respring:(id)sender {
	if([[NSFileManager defaultManager] fileExistsAtPath:JBPath(@"/usr/bin/sbreload")]) {
		pid_t pid;
		const char *args[] = {"sbreload", NULL, NULL, NULL};
		posix_spawn(&pid, [JBPath(@"/usr/bin/sbreload") fileSystemRepresentation], NULL, NULL, (char *const *)args, NULL);
	} else {
		pid_t pid;
		const char *args[] = {"killall", "-9", "SpringBoard", NULL};
		posix_spawn(&pid, [JBPath(@"/usr/bin/killall") fileSystemRepresentation], NULL, NULL, (char *const *)args, NULL);
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
	NSData* data = [NSPropertyListSerialization dataWithPropertyList:[prefs dictionaryRepresentation] format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];

	if(!data) {
		return;
	}

	NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ShadowSettings.plist"];
	if(![data writeToFile:path atomically:YES]) {
		return;
	}

	UIActivityViewController* avc = [[UIActivityViewController alloc] initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
	avc.popoverPresentationController.sourceView = self.view;
	avc.popoverPresentationController.sourceRect = self.view.bounds;
	[self presentViewController:avc animated:YES completion:nil];
}

- (void)importSettings:(id)sender {
	activePicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[(NSString *)kUTTypePropertyList] inMode:UIDocumentPickerModeImport];
	activePicker.delegate = self;
	[self presentViewController:activePicker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
	if(urls.count == 0) {
		return;
	}

	NSData* data = [NSData dataWithContentsOfURL:urls[0]];
	NSDictionary* imported = nil;

	if(data) {
		id plist = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];

		if([plist isKindOfClass:[NSDictionary class]]) {
			imported = plist;
		}
	}

	if(!imported) {
		UIAlertController* bad = [UIAlertController alertControllerWithTitle:[self localized:@"IMPORT_BAD_FILE" fallback:@"The selected file is not a valid Shadow settings backup."] message:nil preferredStyle:UIAlertControllerStyleAlert];
		[bad addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_OK" fallback:@"OK"] style:UIAlertActionStyleDefault handler:nil]];
		[self presentViewController:bad animated:YES completion:nil];
		return;
	}

	UIAlertController* confirm = [UIAlertController alertControllerWithTitle:[self localized:@"IMPORT_CONFIRM_TITLE" fallback:@"Import Settings?"] message:[self localized:@"IMPORT_CONFIRM_MSG" fallback:@"This replaces all current settings with the selected file."] preferredStyle:UIAlertControllerStyleAlert];

	[confirm addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_CANCEL" fallback:@"Cancel"] style:UIAlertActionStyleCancel handler:nil]];
	[confirm addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_CONFIRM" fallback:@"Import"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
		NSDictionary* prefs_dict = [prefs dictionaryRepresentation];
		for(id key in prefs_dict) {
			[prefs removeObjectForKey:key];
		}

		for(id key in imported) {
			[prefs setObject:imported[key] forKey:key];
		}

		[prefs synchronize];

		UIAlertController* applied = [UIAlertController alertControllerWithTitle:[self localized:@"IMPORT_APPLIED" fallback:@"Settings imported. Respring to apply."] message:nil preferredStyle:UIAlertControllerStyleAlert];
		[applied addAction:[UIAlertAction actionWithTitle:[self localized:@"IMPORT_OK" fallback:@"OK"] style:UIAlertActionStyleDefault handler:nil]];
		[self presentViewController:applied animated:YES completion:nil];
	}]];

	[self presentViewController:confirm animated:YES completion:nil];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
	// no-op; the picker was dismissed by the user.
}

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
