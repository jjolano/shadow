#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#import "SHDWAboutListController.h"

@implementation SHDWAboutListController {
	NSString* packageVersion;
	NSString* latestVersion;
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
		packageVersion = nil;
		latestVersion = nil;
	}

	return self;
}
@end
