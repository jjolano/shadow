#import "SHDWRootListController.h"

#import <Shadow/Core+Utilities.h>
#import <Shadow/Settings.h>

#import <RootBridge.h>

@implementation SHDWRootListController {
	NSUserDefaults* prefs;
}

- (NSArray *)specifiers {
	if(!_specifiers) {
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	}

	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
	return [prefs objectForKey:[specifier identifier]];
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	[prefs setObject:value forKey:[specifier identifier]];
	[prefs synchronize];
}

- (void)respring:(id)sender {
	if([[NSFileManager defaultManager] fileExistsAtPath:[RootBridge getJBPath:@"/usr/bin/sbreload"]]) {
		pid_t pid;
		const char *args[] = {"sbreload", NULL, NULL, NULL};
		posix_spawn(&pid, [[RootBridge getJBPath:@"/usr/bin/sbreload"] fileSystemRepresentation], NULL, NULL, (char *const *)args, NULL);
	} else {
		pid_t pid;
		const char *args[] = {"killall", "-9", "SpringBoard", NULL};
		posix_spawn(&pid, [[RootBridge getJBPath:@"/usr/bin/killall"] fileSystemRepresentation], NULL, NULL, (char *const *)args, NULL);
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

- (instancetype)init {
	if((self = [super init])) {
		prefs = [[ShadowSettings sharedInstance] userDefaults];
	}

	return self;
}
@end
