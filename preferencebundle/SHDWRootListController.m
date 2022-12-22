#import "SHDWRootListController.h"
#import "../api/ShadowService+Settings.h"

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
	return @([prefs boolForKey:[specifier identifier]]);
}

- (void)setPreferenceValue:(id)value forSpecifier:(PSSpecifier *)specifier {
	[prefs setObject:value forKey:[specifier identifier]];
	[prefs synchronize];
}

- (void)respring:(id)sender {
	// Check if we are in a rootless environment.
	NSDictionary* jb_attr = [[NSFileManager defaultManager] attributesOfItemAtPath:@"/var/jb" error:nil];
	BOOL rootless = [jb_attr[NSFileType] isEqualToString:NSFileTypeSymbolicLink];

	if(rootless) {
		if([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb/usr/bin/sbreload"]) {
			pid_t pid;
			const char *args[] = {"sbreload", NULL, NULL, NULL};
			posix_spawn(&pid, "/var/jb/usr/bin/sbreload", NULL, NULL, (char *const *)args, NULL);
		} else {
			pid_t pid;
			const char *args[] = {"killall", "-9", "SpringBoard", NULL};
			posix_spawn(&pid, "/var/jb/usr/bin/killall", NULL, NULL, (char *const *)args, NULL);
		}
	} else {
		if([[NSFileManager defaultManager] fileExistsAtPath:@"/usr/bin/sbreload"]) {
			pid_t pid;
			const char *args[] = {"sbreload", NULL, NULL, NULL};
			posix_spawn(&pid, "/usr/bin/sbreload", NULL, NULL, (char *const *)args, NULL);
		} else {
			pid_t pid;
			const char *args[] = {"killall", "-9", "SpringBoard", NULL};
			posix_spawn(&pid, "/usr/bin/killall", NULL, NULL, (char *const *)args, NULL);
		}
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
		prefs = [ShadowService getUserDefaults];
	}

	return self;
}
@end
