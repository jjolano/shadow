// Shadow by jjolano
// Simple jailbreak detection blocker tested on iOS 12.1.2.

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>

%group sandboxed

bool is_jb_path(NSString *path) {
	return (
		[path hasPrefix:@"/Applications/"]
		|| [path hasPrefix:@"/Library/MobileSubstrate"]
		|| [path hasPrefix:@"/Library/substrate"]
		|| [path hasPrefix:@"/Library/TweakInject"]
		|| [path hasPrefix:@"/Library/LaunchDaemons/"]
		|| [path hasPrefix:@"/Library/PreferenceBundles"]
		|| [path hasPrefix:@"/Library/PreferenceLoader"]
		|| [path hasPrefix:@"/Library/Switches"]
		|| [path hasPrefix:@"/Library/Themes"]
		|| [path hasPrefix:@"/Library/dpkg"]
		|| [path hasPrefix:@"/jb"]
		|| [path hasPrefix:@"/electra"]
		|| [path hasPrefix:@"/bin"]
		|| [path hasPrefix:@"/sbin"]
		|| [path hasPrefix:@"/var/cache/apt"]
		|| [path hasPrefix:@"/var/lib"]
		|| [path hasPrefix:@"/var/log"]
		|| [path isEqualToString:@"/var/tmp/cydia.log"]
		|| [path isEqualToString:@"/var/tmp/syslog"]
		|| [path isEqualToString:@"/var/tmp/slide.txt"]
		|| [path hasPrefix:@"/private/var/cache/apt"]
		|| [path hasPrefix:@"/private/var/lib"]
		|| [path hasPrefix:@"/private/var/log"]
		|| [path isEqualToString:@"/private/var/tmp/cydia.log"]
		|| [path isEqualToString:@"/private/var/tmp/syslog"]
		|| [path isEqualToString:@"/private/var/tmp/slide.txt"]
		|| [path hasPrefix:@"/usr/bin"]
		|| [path hasPrefix:@"/usr/sbin"]
		|| [path hasPrefix:@"/usr/libexec"]
		|| [path hasPrefix:@"/usr/share/dpkg"]
		|| [path hasPrefix:@"/usr/share/bigboss"]
		|| [path hasPrefix:@"/usr/share/jailbreak"]
		|| [path hasPrefix:@"/usr/share/entitlements"]
		|| [path hasPrefix:@"/usr/local"]
		|| [path hasPrefix:@"/usr/lib"]
		|| [path hasPrefix:@"/usr/include"]
		|| [path hasPrefix:@"/etc/alternatives"]
		|| [path hasPrefix:@"/etc/apt"]
		|| [path hasPrefix:@"/etc/dpkg"]
		|| [path hasPrefix:@"/."]
	);
}

bool is_jb_path_c(const char *path) {
	return (
		strstr(path, "/Applications/") == path
		|| strstr(path, "/Library/MobileSubstrate") == path
		|| strstr(path, "/Library/substrate") == path
		|| strstr(path, "/Library/TweakInject") == path
		|| strstr(path, "/Library/LaunchDaemons/") == path
		|| strstr(path, "/Library/PreferenceBundles") == path
		|| strstr(path, "/Library/PreferenceLoader") == path
		|| strstr(path, "/Library/Switches") == path
		|| strstr(path, "/Library/Themes") == path
		|| strstr(path, "/Library/dpkg") == path
		|| strstr(path, "/jb") == path
		|| strstr(path, "/electra") == path
		|| strstr(path, "/bin") == path
		|| strstr(path, "/sbin") == path
		|| strstr(path, "/var/cache/apt") == path
		|| strstr(path, "/var/lib") == path
		|| strstr(path, "/var/log") == path
		|| strcmp(path, "/var/tmp/cydia.log") == 0
		|| strcmp(path, "/var/tmp/syslog") == 0
		|| strcmp(path, "/var/tmp/slide.txt") == 0
		|| strstr(path, "/private/var/cache/apt") == path
		|| strstr(path, "/private/var/lib") == path
		|| strstr(path, "/private/var/log") == path
		|| strcmp(path, "/private/var/tmp/cydia.log") == 0
		|| strcmp(path, "/private/var/tmp/syslog") == 0
		|| strcmp(path, "/private/var/tmp/slide.txt") == 0
		|| strstr(path, "/usr/bin") == path
		|| strstr(path, "/usr/sbin") == path
		|| strstr(path, "/usr/libexec") == path
		|| strstr(path, "/usr/share/dpkg") == path
		|| strstr(path, "/usr/share/bigboss") == path
		|| strstr(path, "/usr/share/jailbreak") == path
		|| strstr(path, "/usr/share/entitlements") == path
		|| strstr(path, "/usr/local") == path
		|| strstr(path, "/usr/lib") == path
		|| strstr(path, "/usr/include") == path
		|| strstr(path, "/etc/alternatives") == path
		|| strstr(path, "/etc/apt") == path
		|| strstr(path, "/etc/dpkg") == path
		|| strstr(path, "/.") == path
	);
}

%hook NSString
- (BOOL)writeToFile:
	(NSString *) path
	atomically:(BOOL)useAuxiliaryFile
	encoding:(NSStringEncoding)enc
	error:(NSError * _Nullable *)error {
	if([path hasPrefix:@"/private"]) {
		NSLog(@"[shadow] blocked writeToFile with path %@", path);
		*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		return NO;
	}

	return %orig;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] blocked fileExistsAtPath with path %@", path);
		return NO;
	}

	// NSLog(@"[shadow] allowed fileExistsAtPath with path %@", path);
	return %orig;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:
	(NSString *)path
	error:(NSError * _Nullable *)error {

	if(is_jb_path(path)) {
		NSLog(@"[shadow] detected contentsOfDirectoryAtPath: %@", path);
	}

	return %orig;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		NSLog(@"[shadow] detected enumeratorAtPath: %@", path);
	}

	return %orig;
}
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
	if([[url scheme] isEqualToString:@"cydia"]
	|| [[url scheme] isEqualToString:@"sileo"]) {
		NSLog(@"[shadow] blocked canOpenURL for scheme %@", [url scheme]);
		return NO;
	}

	return %orig;
}
%end

%hookf(DIR *, opendir, const char *name) {
	if(is_jb_path_c(name)) {
		NSLog(@"[shadow] blocked opendir: %s", name);
		return NULL;
	}

	return %orig;
}

// Seems to be disabled in the SDK. Probably no point hooking this.
%hookf(int, "system", const char *command) {
	if(command == NULL) {
		return 0;
	}

	return %orig;
}

%hookf(pid_t, fork) {
	NSLog(@"[shadow] blocked fork");
	return -1;
}

%hookf(char *, getenv, const char *name) {
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

	return %orig;
}

// This hook seems to cause problems? Maybe it's used by Substrate itself.
%hookf(int, open, const char *pathname, int flags) {
	if(is_jb_path_c(pathname) && strstr(pathname, "DynamicLibraries") == NULL) {
		NSLog(@"[shadow] blocked open with path %s", pathname);
		return -1;
	}

	return %orig;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
	// Handle special cases.
	if(strcmp(pathname, "/Applications") == 0
	|| strcmp(pathname, "/Library/Ringtones") == 0
	|| strcmp(pathname, "/Library/Wallpaper") == 0
	|| strcmp(pathname, "/usr/arm-apple-darwin9") == 0
	|| strcmp(pathname, "/usr/include") == 0
	|| strcmp(pathname, "/usr/libexec") == 0
	|| strcmp(pathname, "/usr/share") == 0) {
		return %orig;
	}

	if(is_jb_path_c(pathname)) {
		NSLog(@"[shadow] blocked stat with path %s", pathname);
		return -1;
	}

	int ret = %orig;

	if(ret == 0 && strcmp(pathname, "/") == 0) {
		// Ensure root is not seen as writable.
		statbuf->st_mode &= ~S_IWUSR;
		statbuf->st_mode &= ~S_IWGRP;
		statbuf->st_mode &= ~S_IWOTH;
	}

	return ret;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
	// Handle special cases.
	if(strcmp(pathname, "/Applications") == 0
	|| strcmp(pathname, "/Library/Ringtones") == 0
	|| strcmp(pathname, "/Library/Wallpaper") == 0
	|| strcmp(pathname, "/usr/arm-apple-darwin9") == 0
	|| strcmp(pathname, "/usr/include") == 0
	|| strcmp(pathname, "/usr/libexec") == 0
	|| strcmp(pathname, "/usr/share") == 0) {
		// Use regular stat.
		NSLog(@"[shadow] lstat on common relocated directories: %s", pathname);
		return stat(pathname, statbuf);
	}

	if(is_jb_path_c(pathname)) {
		NSLog(@"[shadow] blocked lstat with path %s", pathname);
		return -1;
	}

	int ret = %orig;

	if(ret == 0 && strcmp(pathname, "/") == 0) {
		// Ensure root is not seen as writable.
		statbuf->st_mode &= ~S_IWUSR;
		statbuf->st_mode &= ~S_IWGRP;
		statbuf->st_mode &= ~S_IWOTH;
	}

	return ret;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
	const char *ret = %orig;

	if(ret != NULL) {
		if(strstr(ret, "MobileSubstrate") != NULL
		|| strstr(ret, "substrate") != NULL
		|| strstr(ret, "substitute") != NULL
		|| strstr(ret, "TweakInject") != NULL) {
			return "";
		}
	}

	return ret;
}

%end

%ctor {
	NSString *executablePath = [[NSBundle mainBundle] executablePath];

	// Only hook for sandboxed user apps.
	if([executablePath hasPrefix:@"/var/containers"]) {
		NSLog(@"[shadow] enabled hooks");
		%init(sandboxed);
	}
}
