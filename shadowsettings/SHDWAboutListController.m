#import "SHDWAboutListController.h"
#import "../api/NSTask.h"

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

- (NSString *)aboutBypassVersion:(id)sender {
	return @BYPASS_VERSION;
}

- (NSString *)aboutAPIVersion:(id)sender {
	return @API_VERSION;
}

- (NSString *)aboutBuildDate:(id)sender {
	NSString* build = [NSString stringWithFormat:@"%@ %@", @__DATE__, @__TIME__];
	return build;
}

- (NSString *)aboutSoftwareLicense:(id)sender {
	return @"BSD 3-Clause";
}

- (NSString *)aboutDeveloper:(id)sender {
	return @"jjolano";
}

- (NSString *)aboutPackageVersion:(id)sender {
	if(packageVersion) {
		return packageVersion;
	}
	
	NSTask* task = [NSTask new];
	NSPipe* stdoutPipe = [NSPipe new];

	[task setLaunchPath:@"/usr/bin/dpkg-query"];
	[task setArguments:@[@"-W", @"me.jjolano.shadow"]];
	[task setStandardOutput:stdoutPipe];
	[task launch];
	[task waitUntilExit];

	if([task terminationStatus] == 0) {
		NSData* data = [[stdoutPipe fileHandleForReading] readDataToEndOfFile];
		NSString* output = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];

		NSCharacterSet* separator = [NSCharacterSet newlineCharacterSet];
		NSArray<NSString *>* lines = [output componentsSeparatedByCharactersInSet:separator];

		for(NSString* entry in lines) {
			NSArray<NSString *>* line = [entry componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
			packageVersion = [line lastObject];
			break;
		}
	} else {
		packageVersion = @"unknown";
	}

	return packageVersion;
}

- (NSString *)aboutLatestVersion:(id)sender {
	if(latestVersion) {
		return latestVersion;
	}

	NSURLRequest* request = [[NSURLRequest alloc] initWithURL:[NSURL URLWithString:@"https://api.github.com/repos/jjolano/shadow/releases/latest"]];

	__block NSDictionary* json;
	[NSURLConnection sendAsynchronousRequest:request queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
		if(!connectionError) {
			json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
			latestVersion = [json[@"tag_name"] substringFromIndex:1];
		} else {
			latestVersion = @"unknown";
		}

		[self reloadSpecifier:sender];
	}];

	return latestVersion;
}

- (instancetype)init {
	if((self = [super init])) {
		packageVersion = nil;
		latestVersion = nil;
	}

	return self;
}
@end
