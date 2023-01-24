#import "SHDWAboutListController.h"

#import "../vendor/apple/NSTask.h"
#import <Shadow/ShadowService.h>

@implementation SHDWAboutListController {
	NSString* packageVersion;
	NSString* latestVersion;
	NSDictionary* versions;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"About" target:self];
	}

	return _specifiers;
}

- (NSString *)aboutBypassVersion:(id)sender {
	return versions[@"bypass_version"];
}

- (NSString *)aboutAPIVersion:(id)sender {
	return versions[@"api_version"];
}

- (NSString *)aboutBuildDate:(id)sender {
	return versions[@"build_date"];
}

- (NSString *)aboutSoftwareLicense:(id)sender {
	return @"BSD 3-Clause";
}

- (NSString *)aboutDeveloper:(id)sender {
	return @"jjolano";
}

- (NSString *)aboutTranslator:(id)sender {
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:@"TRANSLATOR" value:@"Unknown" table:@"About"];
}

- (NSString *)aboutLatestVersion:(id)sender {
	if(latestVersion) {
		return latestVersion;
	}

	NSURL* update_url = [NSURL URLWithString:@"https://api.github.com/repos/jjolano/shadow/releases/latest"];

	NSURLSession* session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:nil delegateQueue:[NSOperationQueue mainQueue]];
	NSURLSessionDataTask* task = [session dataTaskWithURL:update_url completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
		if(!error) {
			NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

			if(json) {
				latestVersion = [json[@"tag_name"] substringFromIndex:1];
			} else {
				latestVersion = @"unknown";
			}
		} else {
			latestVersion = @"unknown";
		}

		[self reloadSpecifier:sender];
	}];

	[task resume];

	return latestVersion;
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
		ShadowService* service = [ShadowService new];

		packageVersion = nil;
		latestVersion = nil;

		versions = [service getVersions];
	}

	return self;
}
@end
