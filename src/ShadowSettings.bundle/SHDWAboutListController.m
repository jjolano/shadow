#import <Shadow/Settings.h>
#import <UIKit/UIKit.h>

#import "SHDWAboutListController.h"
#import "SHDWPrefs.h"
#import "SHDWUpdatesController.h"

@implementation SHDWAboutListController

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"About" target:self];
		SHDWLocalizeSpecifiers(_specifiers, [NSBundle bundleForClass:[self class]], @"About");
		self.title = [self localized:@"ABOUT_TITLE"];

		// Guarded symbols on modern iOS; plain, labeled rows on iOS 9.
		for(NSDictionary* mapping in @[
			@{ @"spec": @"AboutUpdates", @"symbol": @"arrow.down.circle" },
			@{ @"spec": @"AboutGitHub", @"symbol": @"chevron.left.forwardslash.chevron.right" },
			@{ @"spec": @"AboutKofi", @"symbol": @"cup.and.saucer" },
			@{ @"spec": @"AboutReset", @"symbol": @"arrow.counterclockwise" },
		]) {
			PSSpecifier* row = [self specifierForID:mapping[@"spec"]];
			if(row) {
				UIImage* icon = SHDWSettingsSymbol(mapping[@"symbol"]);
				if(icon) {
					[row setProperty:icon forKey:@"iconImage"];
				}
			}
		}
	}

	return _specifiers;
}

- (NSString *)localized:(NSString *)key {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:key value:key table:@"About"];
}

- (NSString *)aboutDeveloper:(id)sender {
	return @"jjolano";
}

- (NSString *)aboutTranslator:(id)sender {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"TRANSLATOR" value:@"Unknown" table:@"About"];
}

- (NSString *)aboutInstalledVersion:(id)sender {
	return SHDWInstalledVersion() ?: [self localized:@"UNKNOWN"];
}

- (void)openGitHub:(id)sender {
	[self openExternalURL:[NSURL URLWithString:@"https://github.com/jjolano/shadow"]];
}

- (void)openKofi:(id)sender {
	[self openExternalURL:[NSURL URLWithString:@"https://ko-fi.com/jjolano"]];
}

- (void)openExternalURL:(NSURL *)url {
	UIApplication* application = [UIApplication sharedApplication];
	if([application respondsToSelector:@selector(openURL:options:completionHandler:)]) {
		[application openURL:url options:@{} completionHandler:nil];
	} else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		[application openURL:url];
#pragma clang diagnostic pop
	}
}

- (void)resetSettings:(id)sender {
	// Destructive: confirm before wiping. Clear the whole persistent domain so
	// the global toggle, aggressive mode, and every per-app override drop back
	// to defaults in one atomic write.
	UIAlertController* alert = [UIAlertController alertControllerWithTitle:[self localized:@"RESET_SETTINGS"] message:[self localized:@"RESET_CONFIRM"] preferredStyle:UIAlertControllerStyleAlert];

	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"RESET_CANCEL"] style:UIAlertActionStyleCancel handler:nil]];
	[alert addAction:[UIAlertAction actionWithTitle:[self localized:@"RESET_SETTINGS"] style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
		[[ShadowSettings sharedInstance] reset];
		// Match the switch-flip feedback used across the panes so the wipe
		// registers as a completed state change, not a silent no-op.
		SHDWToggleHaptic();
	}]];

	[self presentViewController:alert animated:YES completion:nil];
}
@end
