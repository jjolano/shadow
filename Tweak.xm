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

const char DYLD_FAKE_NAME[] = "/usr/lib/system/libdyld.dylib";
int DYLD_FAKE_COUNT = -1;

inline bool is_jb_path(NSString *path) {
	if(path == nil) {
		return false;
	}

	if([path hasPrefix:@"/Library"]) {
		if([path hasPrefix:@"/Library/MobileSubstrate"]
		|| [path hasPrefix:@"/Library/substrate"]
		|| [path hasPrefix:@"/Library/TweakInject"]
		|| [path hasPrefix:@"/Library/LaunchDaemons"]
		|| [path hasPrefix:@"/Library/PreferenceBundles"]
		|| [path hasPrefix:@"/Library/PreferenceLoader"]
		|| [path hasPrefix:@"/Library/Switches"]
		|| [path hasPrefix:@"/Library/dpkg"]
		|| [path hasPrefix:@"/Library/Caches"]
		|| [path hasPrefix:@"/Library/ControlCenter"]
		|| [path hasPrefix:@"/Library/Frameworks"]
		|| [path hasPrefix:@"/Library/Karen"]
		|| [path hasPrefix:@"/Library/Cylinder"]
		|| [path hasPrefix:@"/Library/Zeppelin"]
		|| [path hasPrefix:@"/Library/CustomFonts"]) {
			return true;
		}

		return false;
	}

	if([path hasPrefix:@"/usr"]) {
		if([path hasPrefix:@"/usr/lib/log"]
		|| [path hasPrefix:@"/usr/local/lib/log"]) {
			return false;
		}

		if([path hasPrefix:@"/usr/share"]) {
			if([path hasPrefix:@"/usr/share/dpkg"]
			|| [path hasPrefix:@"/usr/share/bigboss"]
			|| [path hasPrefix:@"/usr/share/jailbreak"]
			|| [path hasPrefix:@"/usr/share/entitlements"]
			|| [path hasPrefix:@"/usr/share/gnupg"]
			|| [path hasPrefix:@"/usr/share/tabset"]
			|| [path hasPrefix:@"/usr/share/terminfo"]) {
				return true;
			}

			return false;
		}

		if([path hasPrefix:@"/usr/bin"]
		|| [path hasPrefix:@"/usr/sbin"]
		|| [path hasPrefix:@"/usr/lib"]
		|| [path hasPrefix:@"/usr/local"]
		|| [path hasPrefix:@"/usr/include"]) {
			return true;
		}

		return false;
	}

	if([path hasPrefix:@"/private"]) {
		if([path hasPrefix:@"/private/etc"]) {
			if([path hasPrefix:@"/private/etc/alternatives"]
			|| [path hasPrefix:@"/private/etc/apt"]
			|| [path hasPrefix:@"/private/etc/dpkg"]
			|| [path hasPrefix:@"/private/etc/dropbear"]
			|| [path hasPrefix:@"/private/etc/ssh"]
			|| [path hasPrefix:@"/private/etc/pam.d"]
			|| [path hasPrefix:@"/private/etc/profile"]
			|| [path hasPrefix:@"/private/etc/ssl"]
			|| [path hasPrefix:@"/private/etc/default"]) {
				return true;
			}

			if([path isEqualToString:@"/private/etc/rc.d/substrate"]
			|| [path isEqualToString:@"/private/etc/motd"]) {
				return true;
			}

			return false;
		}

		if([path hasPrefix:@"/private/var"]) {
			if([path hasPrefix:@"/private/var/tmp"]) {
				if([path hasPrefix:@"/private/var/tmp/substrate"]
				|| [path hasPrefix:@"/private/var/tmp/Substrate"]) {
					return true;
				}

				if([path isEqualToString:@"/private/var/tmp/cydia.log"]
				|| [path isEqualToString:@"/private/var/tmp/syslog"]
				|| [path isEqualToString:@"/private/var/tmp/slide.txt"]
				|| [path isEqualToString:@"/private/var/tmp/amfidebilitate.out"]) {
					return true;
				}

				return false;
			}

			if([path hasPrefix:@"/private/var/mobile"]) {
				if([path hasPrefix:@"/private/var/mobile/Library/Cydia"]
				|| [path hasPrefix:@"/private/var/mobile/Library/Logs/Cydia"]
				|| [path hasPrefix:@"/private/var/mobile/Library/SBSettings"]
				|| [path hasPrefix:@"/private/var/mobile/Media/panguaxe"]) {
					return true;
				}

				return false;
			}

			if([path hasPrefix:@"/private/var/cache/apt"]
			|| [path hasPrefix:@"/private/var/lib"]
			|| [path hasPrefix:@"/private/var/log/"]
			|| [path hasPrefix:@"/private/var/stash"]
			|| [path hasPrefix:@"/private/var/db/stash"]
			|| [path hasPrefix:@"/private/var/rocket_stashed"]
			|| [path hasPrefix:@"/private/var/tweak"]) {
				return true;
			}

			// rootlessJB
			if([path hasPrefix:@"/private/var/LIB"]
			|| [path hasPrefix:@"/private/var/ulb"]
			|| [path hasPrefix:@"/private/var/bin"]
			|| [path hasPrefix:@"/private/var/sbin"]
			|| [path hasPrefix:@"/private/var/profile"]
			|| [path hasPrefix:@"/private/var/motd"]
			|| [path hasPrefix:@"/private/var/dropbear"]) {
				return true;
			}
		}

		return false;
	}

	if([path hasPrefix:@"/User"]) {
		if([path hasPrefix:@"/User/Library/Cydia"]
		|| [path hasPrefix:@"/User/Library/Logs/Cydia"]
		|| [path hasPrefix:@"/User/Library/SBSettings"]
		|| [path hasPrefix:@"/User/Media/panguaxe"]) {
			return true;
		}

		return false;
	}

	if([path hasPrefix:@"/etc"]) {
		if([path hasPrefix:@"/etc/alternatives"]
		|| [path hasPrefix:@"/etc/apt"]
		|| [path hasPrefix:@"/etc/dpkg"]
		|| [path hasPrefix:@"/etc/dropbear"]
		|| [path hasPrefix:@"/etc/ssh"]
		|| [path hasPrefix:@"/etc/pam.d"]
		|| [path hasPrefix:@"/etc/profile"]
		|| [path hasPrefix:@"/etc/ssl"]
		|| [path hasPrefix:@"/etc/default"]) {
			return true;
		}

		if([path isEqualToString:@"/etc/rc.d/substrate"]
		|| [path isEqualToString:@"/etc/motd"]) {
			return true;
		}

		return false;
	}
	
	if([path hasPrefix:@"/var"]) {
		if([path hasPrefix:@"/var/tmp"]) {
			if([path hasPrefix:@"/var/tmp/substrate"]
			|| [path hasPrefix:@"/var/tmp/Substrate"]) {
				return true;
			}

			if([path isEqualToString:@"/var/tmp/cydia.log"]
			|| [path isEqualToString:@"/var/tmp/syslog"]
			|| [path isEqualToString:@"/var/tmp/slide.txt"]
			|| [path isEqualToString:@"/var/tmp/amfidebilitate.out"]) {
				return true;
			}

			return false;
		}

		if([path hasPrefix:@"/var/mobile"]) {
			if([path hasPrefix:@"/var/mobile/Library/Cydia"]
			|| [path hasPrefix:@"/var/mobile/Library/Logs/Cydia"]
			|| [path hasPrefix:@"/var/mobile/Library/SBSettings"]
			|| [path hasPrefix:@"/var/mobile/Media/panguaxe"]) {
				return true;
			}

			return false;
		}

		if([path hasPrefix:@"/var/cache/apt"]
		|| [path hasPrefix:@"/var/lib"]
		|| [path hasPrefix:@"/var/log/"]
		|| [path hasPrefix:@"/var/stash"]
		|| [path hasPrefix:@"/var/db/stash"]
		|| [path hasPrefix:@"/var/rocket_stashed"]
		|| [path hasPrefix:@"/var/tweak"]) {
			return true;
		}

		// rootlessJB
		if([path hasPrefix:@"/var/LIB"]
		|| [path hasPrefix:@"/var/ulb"]
		|| [path hasPrefix:@"/var/bin"]
		|| [path hasPrefix:@"/var/sbin"]
		|| [path hasPrefix:@"/var/profile"]
		|| [path hasPrefix:@"/var/motd"]
		|| [path hasPrefix:@"/var/dropbear"]) {
			return true;
		}
		
		return false;
	}

	if([path hasPrefix:@"/tmp"]) {
		if([path hasPrefix:@"/tmp/substrate"]
		|| [path hasPrefix:@"/tmp/Substrate"]) {
			return true;
		}

		if([path isEqualToString:@"/tmp/cydia.log"]
		|| [path isEqualToString:@"/tmp/syslog"]
		|| [path isEqualToString:@"/tmp/slide.txt"]
		|| [path isEqualToString:@"/tmp/amfidebilitate.out"]) {
			return true;
		}

		return false;
	}

	if([path isEqualToString:@"/.file"]) {
		return false;
	}

	if([path isEqualToString:@"/authorize.sh"]
	|| [path isEqualToString:@"/RWTEST"]) {
		return true;
	}

	if([path hasPrefix:@"/Applications/"]
	|| [path hasPrefix:@"/bin"]
	|| [path hasPrefix:@"/sbin"]
	|| [path hasPrefix:@"/jb"]
	|| [path hasPrefix:@"/electra"]
	|| [path hasPrefix:@"/."]
	|| [path hasPrefix:@"/meridian"]
	|| [path hasPrefix:@"/bootstrap"]
	|| [path hasPrefix:@"/panguaxe"]
	|| [path hasPrefix:@"/taig"]
	|| [path hasPrefix:@"/pguntether"]
	|| [path hasPrefix:@"/OsirisJB"]
	|| [path hasPrefix:@"/chimera"]) {
		return true;
	}

	if([path containsString:@"cydia"]
	|| [path containsString:@"Cydia"]) {
		return true;
	}

	return false;
}

bool is_jb_path_c(const char *path) {
	if(path == NULL) {
		return false;
	}

	return is_jb_path([NSString stringWithUTF8String:path]);
}

%group sandboxed

/*
%hook NSBundle
+ (NSBundle *)bundleWithIdentifier:(NSString *)identifier {
	if([identifier isEqualToString:@"com.saurik.Cydia"]
	|| [identifier isEqualToString:@"com.coolstar.sileo"]) {
		NSLog(@"[shadow] blocked bundleWithIdentifier with identifier %@", identifier);
		return nil;
	}

	return %orig;
}

+ (instancetype)bundleWithPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked bundleWithPath with path %@", path);
		return nil;
	}

	return %orig;
}
%end
*/

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked fileExistsAtPath with path %@", path);
		return NO;
	}

	// NSLog(@"[shadow] allowed fileExistsAtPath with path %@", path);
	return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path
	isDirectory:(BOOL *)isDirectory {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked fileExistsAtPath with path %@", path);
		return NO;
	}

	// NSLog(@"[shadow] allowed fileExistsAtPath with path %@", path);
	return %orig;
}

/*- (BOOL)isReadableFileAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked isReadableFileAtPath with path %@", path);
		return NO;
	}

	// NSLog(@"[shadow] allowed isReadableFileAtPath with path %@", path);
	return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked isExecutableFileAtPath with path %@", path);
		return NO;
	}

	// NSLog(@"[shadow] allowed isExecutableFileAtPath with path %@", path);
	return %orig;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path
	withDestinationPath:(NSString *)destPath
	error:(NSError * _Nullable *)error {
	if(is_jb_path(destPath)) {
		NSLog(@"[shadow] blocked createSymbolicLinkAtPath with destPath %@", destPath);

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath
	toPath:(NSString *)dstPath
	error:(NSError * _Nullable *)error {
	if(is_jb_path(dstPath)) {
		NSLog(@"[shadow] blocked linkItemAtPath with dstPath %@", dstPath);

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path
	error:(NSError * _Nullable *)error {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked destinationOfSymbolicLinkAtPath with path %@", path);

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked subpathsAtPath with path %@", path);
		return nil;
	}

	return %orig;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path
	error:(NSError * _Nullable *)error {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked subpathsOfDirectoryAtPath with path %@", path);

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked enumeratorAtPath with path %@", path);
		return %orig(NSHomeDirectory());
	}

	return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path
	error:(NSError * _Nullable *)error {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked attributesOfItemAtPath with path %@", path);

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (NSString *)displayNameAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked displayNameAtPath with path %@", path);
		return path;
	}

	return %orig;
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked componentsToDisplayForPath with path %@", path);
		return nil;
	}

	return %orig;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path
	error:(NSError * _Nullable *)error {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked contentsOfDirectoryAtPath with path %@", path);

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}*/
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
	if(url == nil) {
		return %orig;
	}

	if([[url scheme] isEqualToString:@"cydia"]
	|| [[url scheme] isEqualToString:@"sileo"]
	|| [[url scheme] isEqualToString:@"zbra"]) {
		NSLog(@"[shadow] blocked canOpenURL for scheme %@", [url scheme]);
		return NO;
	}

	return %orig;
}
%end

%hookf(int, access, const char *pathname, int mode) {
	if(is_jb_path_c(pathname)) {
		if(strstr(pathname, "DynamicLibraries") == NULL) {
			NSLog(@"[shadow] blocked access: %s", pathname);
			return -1;
		}
	}

	// NSLog(@"[shadow] allowed access: %s", pathname);
	return %orig;
}

%hookf(DIR *, opendir, const char *name) {
	if(is_jb_path_c(name)) {
		NSLog(@"[shadow] blocked opendir: %s", name);
		return NULL;
	}

	// NSLog(@"[shadow] allowed opendir: %s", name);
	return %orig;
}

%hookf(char *, getenv, const char *name) {
	if(name == NULL) {
		return %orig;
	}

	if(strcmp(name, "DYLD_INSERT_LIBRARIES") == 0
	|| strcmp(name, "_MSSafeMode") == 0) {
		NSLog(@"[shadow] blocked getenv for %s", name);
		return NULL;
	}

	return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
	if(is_jb_path_c(pathname)) {
		NSLog(@"[shadow] blocked fopen with path %s", pathname);
		return NULL;
	}

	// NSLog(@"[shadow] allowed fopen with path %s", pathname);
	return %orig;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
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
	if(is_jb_path_c(pathname)) {
		NSLog(@"[shadow] blocked stat with path %s", pathname);
		return -1;
	}

	// NSLog(@"[shadow] allowed stat with path %s", pathname);
	return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
	if(is_jb_path_c(pathname)) {
		NSLog(@"[shadow] blocked lstat with path %s", pathname);
		return -1;
	}

	// NSLog(@"[shadow] allowed stat with path %s", pathname);
	return %orig;
}

/*
%hookf(bool, dlopen_preflight, const char* path) {
	if(is_jb_path_c(path)) {
		NSLog(@"[shadow] blocked dlopen_preflight with path %s", path);
		return false;
	}

	return %orig;
}

%hookf(uint32_t, _dyld_image_count) {
	if(DYLD_FAKE_COUNT != -1) {
		return DYLD_FAKE_COUNT;
	}

	return %orig;
}
*/

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
			return DYLD_FAKE_NAME;
		}
	}

	return ret;
}

%end

%ctor {
	NSBundle *bundle = [NSBundle mainBundle];

	if(bundle != nil && ![[bundle bundleIdentifier] hasPrefix:@"com.apple"]) {
		NSString *executablePath = [bundle executablePath];

		// Only hook for non-Apple sandboxed user apps.
		// Maybe todo: implement preferences and whitelist apps from hooks?
		if([executablePath hasPrefix:@"/var/containers/Bundle/Application"]) {
			NSLog(@"[shadow] enabled hooks");
			%init(sandboxed);
		}
	}
}
