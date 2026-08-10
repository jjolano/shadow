#import <Shadow/JBPath.h>

#import "SHDWAboutListController.h"



@implementation SHDWAboutListController {
	NSString* latestVersion;
	BOOL fetchingLatestVersion;
	NSURLSessionDataTask* latestVersionTask;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"About" target:self];
	}

	return _specifiers;
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
		NSString* dpkg_status = [NSString stringWithContentsOfFile:JBPath(@"/var/lib/dpkg/status") encoding:NSUTF8StringEncoding error:nil];

		if(dpkg_status) {
			NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:@"Package: me\\.jjolano\\.shadow\\n[\\s\\S]*?\\nVersion: ([^\\n]+)" options:0 error:nil];
			NSTextCheckingResult* match = [regex firstMatchInString:dpkg_status options:0 range:NSMakeRange(0, dpkg_status.length)];

			if(match) {
				packageVersion = [dpkg_status substringWithRange:[match rangeAtIndex:1]];
			}
		}
	}

	return packageVersion;
}

- (NSString *)aboutLatestVersion:(id)sender {
	if(latestVersion) {
		return latestVersion;
	}

	if(!fetchingLatestVersion) {
		fetchingLatestVersion = YES;

		NSURL* update_url = [NSURL URLWithString:@"https://api.github.com/repos/jjolano/shadow/releases/latest"];

		__weak typeof(self) weakSelf = self;
		__weak typeof(sender) weakSpecifier = sender;

		NSURLSession* session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:nil delegateQueue:[NSOperationQueue mainQueue]];
		latestVersionTask = [session dataTaskWithURL:update_url completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
			typeof(self) strongSelf = weakSelf;

			NSString* version = nil;

			if(!error) {
				NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

				if(json) {
					NSString* tag_name = json[@"tag_name"];

					if(tag_name && tag_name.length > 0) {
						version = [tag_name hasPrefix:@"v"] ? [tag_name substringFromIndex:1] : tag_name;
					}
				}
			}

			// Always reload: the placeholder ("…") cell must be replaced
			// with the fetched version (or "Unknown") on every outcome.
			if(strongSelf) {
				strongSelf->latestVersion = version ?: [[NSBundle bundleForClass:[strongSelf class]] localizedStringForKey:@"UNKNOWN" value:@"Unknown" table:@"About"];
				[strongSelf reloadSpecifier:weakSpecifier];
			}

			[session finishTasksAndInvalidate];
		}];

		[latestVersionTask resume];
	}

	// Placeholder until the fetch completes; reloadSpecifier: re-reads this.
	return @"…";
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
