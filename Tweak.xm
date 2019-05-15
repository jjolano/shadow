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

NSMutableDictionary *jb_map = nil;

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

	[jb_map_usr setValue:@NO forKey:@"/lib/log"];
	[jb_map_usr setValue:@NO forKey:@"/local/lib/log"];
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
	[jb_map setValue:@NO forKey:@"/.file"];
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
	if(!map || !path || ![path respondsToSelector:@selector(hasPrefix:)]) {
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

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:pathname])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked access: %s", pathname);
		#endif

		errno = ENOENT;
		return -1;
	}

	// NSLog(@"[shadow] allowed access: %s", pathname);
	return %orig;
}

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

%hookf(char *, getenv, const char *name) {
	if(!name) {
		return %orig;
	}

	if(strcmp(name, "DYLD_INSERT_LIBRARIES") == 0
	|| strcmp(name, "_MSSafeMode") == 0
	|| strcmp(name, "_SafeMode") == 0) {
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

	if(ret == 0 && strcmp(path, "/") == 0) {
		if(buf != NULL) {
			// Ensure root is marked read-only.
			buf->f_flags |= MNT_RDONLY;
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

%hookf(bool, dlopen_preflight, const char* path) {
	if(!path) {
		return %orig;
	}

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:path])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked dlopen_preflight with path %s", path);
		#endif

		return false;
	}

	return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
	const char *ret = %orig;

	if(ret != NULL) {
		if(strstr(ret, "MobileSubstrate") != NULL
		|| strstr(ret, "substrate") != NULL
		|| strstr(ret, "substitute") != NULL
		|| strstr(ret, "TweakInject") != NULL
		|| strstr(ret, "libjailbreak") != NULL
		|| strstr(ret, "cycript") != NULL
		|| strstr(ret, "SBInject") != NULL
		|| strstr(ret, "pspawn") != NULL) {
			return "/usr/lib/system/libdyld.dylib";
		}
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
			bool should_hook = true;
			NSString *bundleIdentifier = [bundle bundleIdentifier];

			// Check bundleIdentifier if it is excluded from bypass hooks.
			#ifdef DEBUG
			NSLog(@"[shadow] bundleIdentifier: %@", bundleIdentifier);
			#endif

			NSArray *excluded_bundleids = @[
				@"com.apple", // Apple apps
				@"is.workflow.my.app" // Shortcuts
			];

			for(NSString *bundle_id in excluded_bundleids) {
				if([bundleIdentifier hasPrefix:bundle_id]) {
					should_hook = false;
					break;
				}
			}

			// Load preference file
			NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
			
			if(prefs) {
				if(prefs[@"enabled"] && ![prefs[@"enabled"] boolValue]) {
					// Shadow disabled in preferences
					should_hook = false;
				}

				if(prefs[bundleIdentifier] && [prefs[bundleIdentifier] boolValue]) {
					// App blacklisted in preferences
					should_hook = false;
				}
			}

			if(should_hook) {
				#ifdef DEBUG
				NSLog(@"[shadow] bypass hooks enabled");
				#endif

				%init(sandboxed_app_hooks);

				// Allocate and initialize restricted paths map.
				init_jb_map();
			}
		}
	}
}
