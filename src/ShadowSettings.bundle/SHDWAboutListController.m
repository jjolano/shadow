#import <Shadow/JBPath.h>
#import <Shadow/Settings.h>
#import <UIKit/UIKit.h>

#import "SHDWAboutListController.h"
#import "SHDWPrefs.h"



@implementation SHDWAboutListController {
	NSString* latestVersion;
	BOOL fetchingLatestVersion;
	BOOL fetchedLatestVersion;
	NSURLSessionDataTask* latestVersionTask;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"About" target:self];

		// Mirror the root pane: the actionable rows get small rounded icons so
		// the About options read like the rest of the bundle. systemImageNamed
		// is resolved at runtime: it exists on iOS 13+ and is a nil no-op on
		// older runtimes, which fall back to plain rows. Tint-aware, no asset
		// churn, and no @available link-time helper for the iOS 9 legacy floor.
		NSBundle* bundle = [NSBundle bundleForClass:[self class]];
		for(NSDictionary* mapping in @[
			@{ @"spec": @"AboutChangelog", @"symbol": @"newspaper" },
			@{ @"spec": @"AboutGitHub", @"symbol": @"chevron.left.forwardslash.chevron.right" },
			@{ @"spec": @"AboutKofi", @"symbol": @"cup.and.saucer" },
			@{ @"spec": @"AboutReset", @"symbol": @"arrow.counterclockwise" },
		]) {
			PSSpecifier* row = [self specifierForID:mapping[@"spec"]];
			if(row) {
				UIImage* icon = [UIImage systemImageNamed:mapping[@"symbol"]];
				if(icon) {
					[row setProperty:icon forKey:@"iconImage"];
				}
				(void)bundle;
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
	// Static: the dpkg status file is multi-MB and the pane re-creates this
	// controller on every open — parse once per process, not per pane.
	static NSString* packageVersion;

	if(!packageVersion) {
		// dpkg keeps its status at the real root on rooted jailbreaks, but
		// inside the bootstrap on rootless/roothide. JBPath only prefixes
		// /Library, /usr and /Applications (never /var), so add the
		// bootstrap location explicitly — the fileExistsAtPath check makes
		// the chain a no-op on flavors where the path doesn't exist.
		for(NSString* statusPath in @[
			JBPath(@"/var/lib/dpkg/status"),
			[@THEOS_PACKAGE_INSTALL_PREFIX stringByAppendingString:@"/var/lib/dpkg/status"]
		]) {
			if(![[NSFileManager defaultManager] fileExistsAtPath:statusPath]) {
				continue;
			}

			NSString* dpkg_status = [NSString stringWithContentsOfFile:statusPath encoding:NSUTF8StringEncoding error:nil];

			if(dpkg_status) {
				NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:@"Package: me\\.jjolano\\.shadow\\n[\\s\\S]*?\\nVersion: ([^\\n]+)" options:0 error:nil];
				NSTextCheckingResult* match = [regex firstMatchInString:dpkg_status options:0 range:NSMakeRange(0, dpkg_status.length)];

				if(match) {
					packageVersion = [dpkg_status substringWithRange:[match rangeAtIndex:1]];
					break;
				}
			}
		}
	}

	return packageVersion;
}

- (NSString *)aboutLatestVersion:(id)sender {
	if(fetchedLatestVersion) {
		return latestVersion ?: [self localized:@"UNKNOWN"];
	}

	if(!fetchingLatestVersion) {
		fetchingLatestVersion = YES;

		// The release list, not /releases/latest: GitHub's "latest" is simply
		// the most recently created non-prerelease release, which includes
		// ones published only to host build assets (the frida-gum devkit).
		// Take the newest release whose tag is actually shaped like a version.
		NSURL* update_url = [NSURL URLWithString:@"https://api.github.com/repos/jjolano/shadow/releases?per_page=10"];

		__weak typeof(self) weakSelf = self;

		NSURLSession* session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:nil delegateQueue:[NSOperationQueue mainQueue]];
		latestVersionTask = [session dataTaskWithURL:update_url completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
			typeof(self) strongSelf = weakSelf;

			NSString* version = nil;

			if(!error && [response isKindOfClass:[NSHTTPURLResponse class]] && [(NSHTTPURLResponse *)response statusCode] == 200) {
				id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

				if([json isKindOfClass:[NSArray class]]) {
					// The API returns releases newest-first.
					for(id release in (NSArray *)json) {
						if(![release isKindOfClass:[NSDictionary class]] || [release[@"prerelease"] boolValue]) {
							continue;
						}

						NSString* tag_name = release[@"tag_name"];

						if(![tag_name isKindOfClass:[NSString class]] || tag_name.length == 0) {
							continue;
						}

						NSString* candidate = [tag_name hasPrefix:@"v"] ? [tag_name substringFromIndex:1] : tag_name;

						if([candidate rangeOfString:@"^[0-9]+\\.[0-9]+" options:NSRegularExpressionSearch].location != NSNotFound) {
							version = candidate;
							break;
						}
					}
				}
			}

			// Always reload: the placeholder ("…") cells must be replaced on
			// every outcome. Both rows are looked up by ID rather than reloading
			// the sender, because either one can be the one that starts the fetch.
			if(strongSelf) {
				strongSelf->latestVersion = version;
				strongSelf->fetchedLatestVersion = YES;

				for(NSString* specID in @[@"LatestVersion", @"UpdateStatus"]) {
					PSSpecifier* specifier = [strongSelf specifierForID:specID];

					if(specifier) {
						[strongSelf reloadSpecifier:specifier];
					}
				}
			}

			[session finishTasksAndInvalidate];
		}];

		[latestVersionTask resume];
	}

	// Placeholder until the fetch completes; reloadSpecifier: re-reads this.
	return @"…";
}

- (NSString *)aboutUpdateStatus:(id)sender {
	if(!fetchedLatestVersion) {
		// Kick the fetch off even if this row is read first.
		[self aboutLatestVersion:nil];
		return @"…";
	}

	NSString* installed = [self aboutInstalledVersion:sender];

	if(!installed || !latestVersion) {
		return [self localized:@"UNKNOWN"];
	}

	// ponytail: NSNumericSearch compares digit runs numerically, so 3.10 > 3.9
	// and a Debian revision ("3.5.6-4") sorts above its base tag, which is all
	// this needs. It is not full dpkg version ordering -- no epochs, and "~"
	// sorts high rather than low. Use a real dpkg comparison if pre-release
	// suffixes ever ship in the package version.
	BOOL outdated = [installed compare:latestVersion options:NSNumericSearch] == NSOrderedAscending;

	return [self localized:(outdated ? @"UPDATE_AVAILABLE" : @"UP_TO_DATE")];
}

- (void)openGitHub:(id)sender {
	[[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/jjolano/shadow"] options:@{} completionHandler:nil];
}

- (void)openKofi:(id)sender {
	[[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://ko-fi.com/jjolano"] options:@{} completionHandler:nil];
}

- (void)openChangeLog:(id)sender {
	[[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/jjolano/shadow/releases/latest"] options:@{} completionHandler:nil];
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

- (void)dealloc {
	[latestVersionTask cancel];
}

- (instancetype)init {
	if((self = [super init])) {
		latestVersion = nil;
	}

	return self;
}
@end
