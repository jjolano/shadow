#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "SHDWAboutListController.h"

#import <RootBridge.h>

@implementation SHDWAboutListController {
	NSString* packageVersion;
	NSString* latestVersion;
	BOOL fetchingLatestVersion;
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
	if(!packageVersion) {
		NSString* dpkg_status = [NSString stringWithContentsOfFile:[RootBridge getJBPath:@"/var/lib/dpkg/status"] encoding:NSUTF8StringEncoding error:nil];

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

		NSURLSession* session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:nil delegateQueue:[NSOperationQueue mainQueue]];
		NSURLSessionDataTask* task = [session dataTaskWithURL:update_url completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
			if(!error) {
				NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

				if(json) {
					NSString* tag_name = json[@"tag_name"];

					if(tag_name && tag_name.length > 0) {
						latestVersion = [tag_name hasPrefix:@"v"] ? [tag_name substringFromIndex:1] : tag_name;
					} else {
						latestVersion = @"unknown";
					}
				} else {
					latestVersion = @"unknown";
				}
			} else {
				latestVersion = @"unknown";
			}

			[self reloadSpecifier:sender];
		}];

		[task resume];
	}

	// Placeholder until the fetch completes; reloadSpecifier: re-reads this.
	return @"…";
}

- (void)openGitHub:(id)sender {
	[[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/jjolano/shadow"]];
}

- (void)openKofi:(id)sender {
	[[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://ko-fi.com/jjolano"]];
}

- (void)openChangeLog:(id)sender {
	[[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://github.com/jjolano/shadow/releases/latest"]];
}

- (instancetype)init {
	if((self = [super init])) {
		packageVersion = nil;
		latestVersion = nil;
	}

	return self;
}
@end
