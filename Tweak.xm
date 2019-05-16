// Shadow by jjolano
// Simple jailbreak detection blocker tested on iOS 12.1.2 (unc0ver).

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <dlfcn.h>
#include <spawn.h>
#include <errno.h>

#include "codesign.h"

NSMutableDictionary *jb_map = nil;
NSMutableArray *dyld_clean_array = nil;
uint32_t dyld_clean_array_count = 0;
BOOL generated_dyld_array = NO;

BOOL use_access_workaround = YES;

void generate_dyld_array(uint32_t count) {
	if(dyld_clean_array) {
		[dyld_clean_array removeAllObjects];
	} else {
		dyld_clean_array = [NSMutableArray new];
	}

	dyld_clean_array_count = 0;
	generated_dyld_array = NO;

	for(int i = 0; i < count; i++) {
		const char *cname = _dyld_get_image_name(i);

		if(cname) {
			NSString *name = [NSString stringWithUTF8String:cname];

			if([name containsString:@"MobileSubstrate"]
			|| [name containsString:@"substrate"]
			|| [name containsString:@"substitute"]
			|| [name containsString:@"TweakInject"]
			|| [name containsString:@"libjailbreak"]
			|| [name containsString:@"cycript"]
			|| [name containsString:@"SBInject"]
			|| [name containsString:@"pspawn"]
			|| [name containsString:@"applist"]
			|| [name hasPrefix:@"/Library/Frameworks"]
			|| [name hasPrefix:@"/Library/Caches"]
			|| [name containsString:@"librocketbootstrap"]
			|| [name containsString:@"libcolorpicker"]) {
				// Skip adding this to clean dyld array.
				continue;
			}

			// Add this to clean dyld array.
			[dyld_clean_array addObject:name];
			dyld_clean_array_count++;
		}
	}

	generated_dyld_array = YES;
}

void init_jb_map() {
	NSMutableDictionary *jb_map_etc = [[NSMutableDictionary alloc] init];

	[jb_map_etc setValue:@YES forKey:@"/alternatives"];
	[jb_map_etc setValue:@YES forKey:@"/apt"];
	[jb_map_etc setValue:@YES forKey:@"/dpkg"];
	[jb_map_etc setValue:@YES forKey:@"/dropbear"];
	[jb_map_etc setValue:@YES forKey:@"/ssh"];
	[jb_map_etc setValue:@YES forKey:@"/pam.d"];
	[jb_map_etc setValue:@YES forKey:@"/profile"];
	[jb_map_etc setValue:@YES forKey:@"/ssl"];
	[jb_map_etc setValue:@YES forKey:@"/default"];
	[jb_map_etc setValue:@YES forKey:@"/rc.d/substrate"];
	[jb_map_etc setValue:@YES forKey:@"/motd"];

	NSMutableDictionary *jb_map_tmp = [[NSMutableDictionary alloc] init];

	[jb_map_tmp setValue:@YES forKey:@"/substrate"];
	[jb_map_tmp setValue:@YES forKey:@"/Substrate"];
	[jb_map_tmp setValue:@YES forKey:@"/cydia.log"];
	[jb_map_tmp setValue:@YES forKey:@"/syslog"];
	[jb_map_tmp setValue:@YES forKey:@"/slide.txt"];
	[jb_map_tmp setValue:@YES forKey:@"/amfidebilitate.out"];

	NSMutableDictionary *jb_map_mobile = [[NSMutableDictionary alloc] init];
	
	[jb_map_mobile setValue:@YES forKey:@"/Library/Cydia"];
	[jb_map_mobile setValue:@YES forKey:@"/Library/Logs/Cydia"];
	[jb_map_mobile setValue:@YES forKey:@"/Library/SBSettings"];
	[jb_map_mobile setValue:@YES forKey:@"/Media/panguaxe"];

	NSMutableDictionary *jb_map_var = [[NSMutableDictionary alloc] init];
	
	[jb_map_var setValue:jb_map_tmp forKey:@"/tmp"];
	[jb_map_var setValue:jb_map_mobile forKey:@"/mobile"];
	[jb_map_var setValue:@YES forKey:@"/cache/apt"];
	[jb_map_var setValue:@YES forKey:@"/lib"];
	[jb_map_var setValue:@YES forKey:@"/log/"];
	[jb_map_var setValue:@YES forKey:@"/stash"];
	[jb_map_var setValue:@YES forKey:@"/db/stash"];
	[jb_map_var setValue:@YES forKey:@"/rocket_stashed"];
	[jb_map_var setValue:@YES forKey:@"/tweak"];
	[jb_map_var setValue:@YES forKey:@"/LIB"];
	[jb_map_var setValue:@YES forKey:@"/ulb"];
	[jb_map_var setValue:@YES forKey:@"/bin"];
	[jb_map_var setValue:@YES forKey:@"/sbin"];
	[jb_map_var setValue:@YES forKey:@"/profile"];
	[jb_map_var setValue:@YES forKey:@"/motd"];
	[jb_map_var setValue:@YES forKey:@"/dropbear"];

	NSMutableDictionary *jb_map_library = [[NSMutableDictionary alloc] init];

	[jb_map_library setValue:@YES forKey:@"/MobileSubstrate"];
	[jb_map_library setValue:@YES forKey:@"/substrate"];
	[jb_map_library setValue:@YES forKey:@"/TweakInject"];
	[jb_map_library setValue:@YES forKey:@"/LaunchDaemons"];
	[jb_map_library setValue:@YES forKey:@"/PreferenceBundles"];
	[jb_map_library setValue:@YES forKey:@"/PreferenceLoader"];
	[jb_map_library setValue:@YES forKey:@"/Switches"];
	[jb_map_library setValue:@YES forKey:@"/dpkg"];
	[jb_map_library setValue:@YES forKey:@"/Caches"];
	[jb_map_library setValue:@YES forKey:@"/ControlCenter"];
	[jb_map_library setValue:@YES forKey:@"/Frameworks"];
	[jb_map_library setValue:@YES forKey:@"/Karen"];
	[jb_map_library setValue:@YES forKey:@"/Cylinder"];
	[jb_map_library setValue:@YES forKey:@"/Zeppelin"];
	[jb_map_library setValue:@YES forKey:@"/CustomFonts"];

	NSMutableDictionary *jb_map_usr_share = [[NSMutableDictionary alloc] init];

	[jb_map_usr_share setValue:@YES forKey:@"/dpkg"];
	[jb_map_usr_share setValue:@YES forKey:@"/bigboss"];
	[jb_map_usr_share setValue:@YES forKey:@"/jailbreak"];
	[jb_map_usr_share setValue:@YES forKey:@"/entitlements"];
	[jb_map_usr_share setValue:@YES forKey:@"/gnupg"];
	[jb_map_usr_share setValue:@YES forKey:@"/tabset"];
	[jb_map_usr_share setValue:@YES forKey:@"/terminfo"];

	NSMutableDictionary *jb_map_usr = [[NSMutableDictionary alloc] init];

	[jb_map_usr setValue:jb_map_usr_share forKey:@"/share"];
	[jb_map_usr setValue:@YES forKey:@"/bin"];
	[jb_map_usr setValue:@YES forKey:@"/sbin"];
	[jb_map_usr setValue:@YES forKey:@"/lib"];
	[jb_map_usr setValue:@YES forKey:@"/local"];
	[jb_map_usr setValue:@YES forKey:@"/include"];

	NSMutableDictionary *jb_map_private = [[NSMutableDictionary alloc] init];

	[jb_map_private setValue:jb_map_etc forKey:@"/etc"];
	[jb_map_private setValue:jb_map_var forKey:@"/var"];

	jb_map = [[NSMutableDictionary alloc] init];

	[jb_map setValue:jb_map_library forKey:@"/Library"];
	[jb_map setValue:jb_map_usr forKey:@"/usr"];
	[jb_map setValue:jb_map_private forKey:@"/private"];
	[jb_map setValue:jb_map_mobile forKey:@"/User"];
	[jb_map setValue:jb_map_etc forKey:@"/etc"];
	[jb_map setValue:jb_map_var forKey:@"/var"];
	[jb_map setValue:jb_map_tmp forKey:@"/tmp"];
	[jb_map setValue:@YES forKey:@"/authorize.sh"];
	[jb_map setValue:@YES forKey:@"/RWTEST"];
	[jb_map setValue:@YES forKey:@"/Applications/"];
	[jb_map setValue:@YES forKey:@"/bin"];
	[jb_map setValue:@YES forKey:@"/sbin"];
	[jb_map setValue:@YES forKey:@"/jb"];
	[jb_map setValue:@YES forKey:@"/electra"];
	[jb_map setValue:@YES forKey:@"/."];
	[jb_map setValue:@YES forKey:@"/meridian"];
	[jb_map setValue:@YES forKey:@"/bootstrap"];
	[jb_map setValue:@YES forKey:@"/panguaxe"];
	[jb_map setValue:@YES forKey:@"/OsirisJB"];
	[jb_map setValue:@YES forKey:@"/chimera"];
}

BOOL is_path_restricted(NSMutableDictionary *map, NSString *path) {
	if(!map || !path || [path length] == 0) {
		return NO;
	}

	// Find key in dictionary.
	for(NSString *key in map) {
		if([path hasPrefix:key]) {
			id val = [map objectForKey:key];

			// Check if value is set.
			if([val isKindOfClass:[NSNumber class]]) {
				return [val boolValue];
			}

			// Recurse into this dictionary.
			return is_path_restricted(val, [path substringFromIndex:[key length]]);
		}
	}

	return NO;
}

%group sandboxed_app_hooks

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileExistsAtPath with path %@", path);
		#endif

		return NO;
	}

	// NSLog(@"[shadow] allowed fileExistsAtPath with path %@", path);
	return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileExistsAtPath with path %@", path);
		#endif

		return NO;
	}

	// NSLog(@"[shadow] allowed fileExistsAtPath with path %@", path);
	return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked isReadableFileAtPath with path %@", path);
		#endif

		return NO;
	}

	// NSLog(@"[shadow] allowed isReadableFileAtPath with path %@", path);
	return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked isExecutableFileAtPath with path %@", path);
		#endif

		return NO;
	}

	// NSLog(@"[shadow] allowed isExecutableFileAtPath with path %@", path);
	return %orig;
}
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
	if(!url) {
		return %orig;
	}

	if([[url scheme] isEqualToString:@"cydia"]
	|| [[url scheme] isEqualToString:@"sileo"]
	|| [[url scheme] isEqualToString:@"zbra"]) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked canOpenURL for scheme %@", [url scheme]);
		#endif

		return NO;
	}

	return %orig;
}
%end

%hookf(int, access, const char *pathname, int mode) {
	if(!pathname) {
		return %orig;
	}

	NSString *path = [NSString stringWithUTF8String:pathname];

	// workaround for tweaks not loading properly - access for anything DynamicLibraries is allowed :x
	if(use_access_workaround && [path hasSuffix:@"plist"] && [path containsString:@"DynamicLibraries/"]) {
		#ifdef DEBUG
		NSLog(@"[shadow] allowed access: %@", path);
		#endif

		return %orig;
	}

	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked access: %@", path);
		#endif

		errno = ENOENT;
		return -1;
	}

	// NSLog(@"[shadow] allowed access: %s", pathname);
	return %orig;
}

/*
// This hook causes issues on Chimera/Substitute apparently.
%hookf(DIR *, opendir, const char *name) {
	if(!name) {
		return %orig;
	}

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:name])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked opendir: %s", name);
		#endif

		errno = ENOENT;
		return NULL;
	}

	// NSLog(@"[shadow] allowed opendir: %s", name);
	return %orig;
}
*/

%hookf(char *, getenv, const char *name) {
	if(!name) {
		return %orig;
	}

	NSString *env = [NSString stringWithUTF8String:name];

	if([env isEqualToString:@"DYLD_INSERT_LIBRARIES"]
	|| [env isEqualToString:@"_MSSafeMode"]
	|| [env isEqualToString:@"_SafeMode"]) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked getenv for %s", name);
		#endif

		return NULL;
	}

	return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
	if(!pathname) {
		return %orig;
	}
	
	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:pathname])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fopen with path %s", pathname);
		#endif

		errno = ENOENT;
		return NULL;
	}

	// NSLog(@"[shadow] allowed fopen with path %s", pathname);
	return %orig;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
	if(!path) {
		return %orig;
	}

	int ret = %orig;

	if(ret == 0) {
		NSString *pathname = [NSString stringWithUTF8String:path];
		
		if([pathname isEqualToString:@"/"]) {
			if(buf != NULL) {
				// Ensure root is marked read-only.
				buf->f_flags |= MNT_RDONLY;
			}
		}
	}

	// NSLog(@"[shadow] statfs on %s", path);
	return ret;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
	if(!pathname) {
		return %orig;
	}

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:pathname])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked stat with path %s", pathname);
		#endif

		errno = ENOENT;
		return -1;
	}

	// NSLog(@"[shadow] allowed stat with path %s", pathname);
	return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
	if(!pathname) {
		return %orig;
	}

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:pathname])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked lstat with path %s", pathname);
		#endif

		errno = ENOENT;
		return -1;
	}

	// NSLog(@"[shadow] allowed stat with path %s", pathname);
	return %orig;
}

%hookf(uint32_t, _dyld_image_count) {
	if(generated_dyld_array) {
		return dyld_clean_array_count;
	}

	return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
	if(generated_dyld_array) {
		// Use generated dyld array.
		if(image_index >= dyld_clean_array_count) {
			return NULL;
		}

		return [dyld_clean_array[image_index] UTF8String];
	}

	// Fallback to masking return value.
	const char *cname = %orig;

	if(cname) {
		NSString *name = [NSString stringWithUTF8String:cname];

		if([name containsString:@"MobileSubstrate"]
		|| [name containsString:@"substrate"]
		|| [name containsString:@"substitute"]
		|| [name containsString:@"TweakInject"]
		|| [name containsString:@"libjailbreak"]
		|| [name containsString:@"cycript"]
		|| [name containsString:@"SBInject"]
		|| [name containsString:@"pspawn"]
		|| [name containsString:@"applist"]
		|| [name hasPrefix:@"/Library/Frameworks"]
		|| [name hasPrefix:@"/Library/Caches"]
		|| [name containsString:@"librocketbootstrap"]
		|| [name containsString:@"libcolorpicker"]) {
			return %orig(0);
		}
	}

	return cname;
}

%end

%group private_methods

%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
	int ret = %orig;

	if(ops == CS_OPS_STATUS && pid == getpid()) {
		// Ensure that the platform binary flag is not set.
		ret &= ~CS_PLATFORM_BINARY;

		#ifdef DEBUG
		NSLog(@"[shadow] csops - removed platform binary flag");
		#endif
	}

	return ret;
}

%end

%ctor {
	NSBundle *bundle = [NSBundle mainBundle];

	if(bundle != nil) {
		NSString *executablePath = [bundle executablePath];

		// Check if this app is executing from sandbox.
		if([executablePath hasPrefix:@"/var/containers/Bundle/Application"]) {
			NSString *bundleIdentifier = [bundle bundleIdentifier];

			// Check bundleIdentifier if it is excluded from bypass hooks.
			#ifdef DEBUG
			NSLog(@"[shadow] bundleIdentifier: %@", bundleIdentifier);
			#endif

			// Load preference file
			NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
			
			if(prefs) {
				if(prefs[@"enabled"] && ![prefs[@"enabled"] boolValue]) {
					// Shadow disabled in preferences
					return;
				}

				if(!prefs[@"exclude_system_apps"] || [prefs[@"exclude_system_apps"] boolValue]) {
					// Disable Shadow for Apple and jailbreak apps
					NSArray *excluded_bundleids = @[
						@"com.apple", // Apple apps
						@"is.workflow.my.app", // Shortcuts
						@"science.xnu.undecimus", // unc0ver
						@"com.electrateam.chimera", // Chimera
						@"org.coolstar.electra1141" // Electra
					];

					for(NSString *bundle_id in excluded_bundleids) {
						if([bundleIdentifier hasPrefix:bundle_id]) {
							return;
						}
					}
				}
				
				if(prefs[@"mode"] && [prefs[@"mode"] isEqualToString:@"whitelist"]) {
					// Whitelist mode
					#ifdef DEBUG
					NSLog(@"[shadow] using %@ mode", prefs[@"mode"]);
					#endif

					if(!prefs[bundleIdentifier] || (prefs[bundleIdentifier] && ![prefs[bundleIdentifier] boolValue])) {
						// App is not whitelisted in preferences
						return;
					}
				} else {
					// Blacklist mode
					#ifdef DEBUG
					NSLog(@"[shadow] using %@ mode", prefs[@"mode"]);
					#endif

					if(prefs[bundleIdentifier] && [prefs[bundleIdentifier] boolValue]) {
						// App is blacklisted in preferences
						return;
					}
				}

				if(!prefs[@"private_methods"] || [prefs[@"enabled"] boolValue]) {
					// Hook private methods
					%init(private_methods);
				}

				if(prefs[@"workaround_access"]) {
					use_access_workaround = [prefs[@"workaround_access"] boolValue];
				}

				if(!prefs[@"dyld_array_enabled"] || [prefs[@"dyld_array_enabled"] boolValue]) {
					// Generate clean dyld array.
					uint32_t dyld_orig_count = _dyld_image_count();
					generate_dyld_array(dyld_orig_count);

					#ifdef DEBUG
					NSLog(@"[shadow] generated clean dyld array (%d/%d)", dyld_clean_array_count, dyld_orig_count);
					#endif
				}
			}

			// Allocate and initialize restricted paths map.
			init_jb_map();

			#ifdef DEBUG
			NSLog(@"[shadow] initialized restricted paths map");
			#endif

			// Hook bypass methods.
			%init(sandboxed_app_hooks);

			#ifdef DEBUG
			NSLog(@"[shadow] bypass hooks enabled");
			#endif
		}
	}
}
