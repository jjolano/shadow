// Shadow by jjolano
// Simple jailbreak detection blocker tested on iOS 12.1.2.

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

%group sandboxed

bool is_jb_path_c(const char *path) {
	return !(strstr(path, "/usr/lib/log") == path) && (
		strstr(path, "../") != NULL
		|| strcmp(path, "/private/var/tmp/cydia.log") == 0
		|| strcmp(path, "/private/var/tmp/Cydia.log") == 0
		|| strcmp(path, "/private/var/tmp/syslog") == 0
		|| strcmp(path, "/private/var/tmp/slide.txt") == 0
		|| strcmp(path, "/private/var/tmp/amfidebilitate.out") == 0
		|| strcmp(path, "/var/tmp/cydia.log") == 0
		|| strcmp(path, "/var/tmp/Cydia.log") == 0
		|| strcmp(path, "/var/tmp/syslog") == 0
		|| strcmp(path, "/var/tmp/slide.txt") == 0
		|| strcmp(path, "/var/tmp/amfidebilitate.out") == 0
		|| strcmp(path, "/tmp/cydia.log") == 0
		|| strcmp(path, "/tmp/Cydia.log") == 0
		|| strcmp(path, "/tmp/syslog") == 0
		|| strcmp(path, "/tmp/slide.txt") == 0
		|| strcmp(path, "/tmp/amfidebilitate.out") == 0
		|| strstr(path, "/Applications/") == path
		|| strstr(path, "/Library/MobileSubstrate") == path
		|| strstr(path, "/Library/substrate") == path
		|| strstr(path, "/Library/TweakInject") == path
		|| strstr(path, "/Library/LaunchDaemons/") == path
		|| strstr(path, "/System/Library/LaunchDaemons/") == path
		|| strstr(path, "/Library/PreferenceBundles") == path
		|| strstr(path, "/Library/PreferenceLoader") == path
		|| strstr(path, "/Library/Switches") == path
		|| strstr(path, "/Library/dpkg") == path
		|| strstr(path, "/jb") == path
		|| strstr(path, "/electra") == path
		|| strstr(path, "/bin") == path
		|| strstr(path, "/sbin") == path
		|| strstr(path, "/var/cache/apt") == path
		|| strstr(path, "/var/lib") == path
		|| strstr(path, "/var/log/") == path
		|| strstr(path, "/var/stash") == path
		|| strstr(path, "/var/db/stash") == path
		|| strstr(path, "/var/mobile/Library/Cydia") == path
		|| strstr(path, "/var/mobile/Library/Logs/Cydia") == path
		|| strstr(path, "/var/mobile/Library/SBSettings") == path
		|| strstr(path, "/private/var/cache/apt") == path
		|| strstr(path, "/private/var/lib") == path
		|| strstr(path, "/private/var/log/") == path
		|| strstr(path, "/private/var/stash") == path
		|| strstr(path, "/private/var/db/stash") == path
		|| strstr(path, "/private/var/mobile/Library/Cydia") == path
		|| strstr(path, "/private/var/mobile/Library/Logs/Cydia") == path
		|| strstr(path, "/private/var/mobile/Library/SBSettings") == path
		|| strstr(path, "/usr/bin") == path
		|| strstr(path, "/usr/sbin") == path
		|| strstr(path, "/usr/libexec/") == path
		|| strstr(path, "/usr/share/dpkg") == path
		|| strstr(path, "/usr/share/bigboss") == path
		|| strstr(path, "/usr/share/jailbreak") == path
		|| strstr(path, "/usr/share/entitlements") == path
		|| strstr(path, "/usr/lib/") == path
		|| strstr(path, "/usr/include") == path
		|| strstr(path, "/etc/alternatives") == path
		|| strstr(path, "/etc/apt") == path
		|| strstr(path, "/etc/dpkg") == path
		|| strstr(path, "/etc/dropbear") == path
		|| strstr(path, "/etc/ssh") == path
		|| strstr(path, "/User/Library/Cydia") == path
		|| strstr(path, "/User/Library/Logs/Cydia") == path
		|| strstr(path, "/.") == path
		|| strstr(path, "/meridian") == path
		|| strstr(path, "/bootstrap") == path
		|| strstr(path, "/panguaxe") == path
		|| strstr(path, "/private/var/mobile/Media/panguaxe") == path
		|| strstr(path, "/taig") == path
		|| strstr(path, "/pguntether") == path
	);
}

bool is_jb_path(NSString *path) {
	return is_jb_path_c([path UTF8String]);
}



bool is_path_sb_readonly(NSString *path) {
	return (
		[path hasPrefix:@"/private"]
		// Exceptions
		&& ![path hasPrefix:@"/private/var/MobileDevice/ProvisioningProfiles"]
		&& ![path hasPrefix:@"/private/var/mobile/Containers/Shared"]
		&& ![path hasPrefix:@"/private/var/mobile/Containers/Data/Application"]
	);
}

%hook NSData
- (BOOL)writeToFile: (NSString *)path
	atomically:(BOOL)useAuxiliaryFile {
	
	if(is_path_sb_readonly(path)) {
		NSLog(@"[shadow] blocked writeToFile with path %@", path);
		return NO;
	}

	return %orig;
}

- (BOOL)writeToFile: (NSString *)path
	options:(NSDataWritingOptions)writeOptionsMask
	error:(NSError * _Nullable *)errorPtr {
	
	if(is_path_sb_readonly(path)) {
		NSLog(@"[shadow] blocked writeToFile with path %@", path);

		if(errorPtr != NULL) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)writeToURL: (NSURL *)url
	atomically:(BOOL)useAuxiliaryFile {
	
	if(is_path_sb_readonly([url path])) {
		NSLog(@"[shadow] blocked writeToFile with path %@", [url path]);
		return NO;
	}

	return %orig;
}

- (BOOL)writeToURL: (NSURL *)url
	options:(NSDataWritingOptions)writeOptionsMask
	error:(NSError * _Nullable *)errorPtr {
	
	if(is_path_sb_readonly([url path])) {
		NSLog(@"[shadow] blocked writeToFile with path %@", [url path]);

		if(errorPtr != nil) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}
%end

%hook NSString
- (BOOL)writeToFile:
	(NSString *)path
	atomically:(BOOL)useAuxiliaryFile
	encoding:(NSStringEncoding)enc
	error:(NSError * _Nullable *)error {
	
	if(is_path_sb_readonly(path)) {
		NSLog(@"[shadow] blocked writeToFile with path %@", path);

		if(error != nil) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)writeToURL:
	(NSURL *)url
	atomically:(BOOL)useAuxiliaryFile
	encoding:(NSStringEncoding)enc
	error:(NSError * _Nullable *)error {
	
	if(is_path_sb_readonly([url path])) {
		NSLog(@"[shadow] blocked writeToURL with path %@", [url path]);

		if(error != nil) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

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

%hookf(int, access, const char *pathname, int mode) {
	if(is_jb_path_c(pathname)) {
		if(strstr(pathname, "DynamicLibraries") == NULL) {
			NSLog(@"[shadow] blocked access: %s", pathname);
			return -1;
		} else {
			// NSLog(@"[shadow] allowed access: %s", pathname);
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

// Seems to be disabled in the SDK (12.2). Probably no point hooking this.
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

%hookf(FILE *, popen, const char *command, const char *type) {
	NSLog(@"[shadow] blocked popen");
	return NULL;
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

	// NSLog(@"[shadow] allowed fopen with path %s", pathname);
	return %orig;
}

// This hook seems to cause problems? Maybe it's used by Substrate itself.
%hookf(int, open, const char *pathname, int flags) {
	if(is_jb_path_c(pathname)) {
		if(strstr(pathname, "DynamicLibraries") == NULL) {
			NSLog(@"[shadow] blocked open with path %s", pathname);
			return -1;
		} else {
			// NSLog(@"[shadow] allowed open with path %s", pathname);
		}
	}

	// NSLog(@"[shadow] allowed open with path %s", pathname);
	return %orig;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
	int ret = %orig;

	if(strcmp(path, "/") == 0) {
		if(buf != NULL) {
			// Ensure root is marked read-only.
			buf->f_flags |= MNT_RDONLY;
		}
	}

	// NSLog(@"[shadow] statfs on %s", path);
	return ret;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
	// Handle special cases.
	if(strcmp(pathname, "/Applications") == 0
	|| strcmp(pathname, "/Library/Ringtones") == 0
	|| strcmp(pathname, "/Library/Wallpaper") == 0
	|| strcmp(pathname, "/usr/arm-apple-darwin9") == 0
	|| strcmp(pathname, "/usr/include") == 0
	|| strcmp(pathname, "/usr/libexec") == 0
	|| strcmp(pathname, "/usr/share") == 0
	|| strcmp(pathname, "/Library") == 0) {
		return %orig;
	}

	if(is_jb_path_c(pathname)) {
		NSLog(@"[shadow] blocked stat with path %s", pathname);
		return -1;
	}

	// NSLog(@"[shadow] allowed stat with path %s", pathname);
	return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
	// Handle special cases.
	if(strcmp(pathname, "/Applications") == 0
	|| strcmp(pathname, "/Library/Ringtones") == 0
	|| strcmp(pathname, "/Library/Wallpaper") == 0
	|| strcmp(pathname, "/usr/arm-apple-darwin9") == 0
	|| strcmp(pathname, "/usr/include") == 0
	|| strcmp(pathname, "/usr/libexec") == 0
	|| strcmp(pathname, "/usr/share") == 0
	|| strcmp(pathname, "/Library") == 0) {
		// Use regular stat.
		NSLog(@"[shadow] lstat on common relocated directories: %s", pathname);
		return stat(pathname, statbuf);
	}

	if(is_jb_path_c(pathname)) {
		NSLog(@"[shadow] blocked lstat with path %s", pathname);
		return -1;
	}

	// NSLog(@"[shadow] allowed stat with path %s", pathname);
	return %orig;
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
	NSBundle *bundle = [NSBundle mainBundle];

	if(bundle != nil) {
		NSString *executablePath = [bundle executablePath];

		// Only hook for sandboxed user apps.
		if([executablePath hasPrefix:@"/var/containers/Bundle/Application"]) {
			NSLog(@"[shadow] enabled hooks");
			%init(sandboxed);
		}
	}
}
