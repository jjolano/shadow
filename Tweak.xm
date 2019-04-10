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

bool is_jb_path(NSString *path) {
	return (
		[path hasPrefix:@"/Applications/"]
		|| [path hasPrefix:@"/Library/MobileSubstrate"]
		|| [path hasPrefix:@"/Library/substrate"]
		|| [path hasPrefix:@"/Library/TweakInject"]
		|| [path hasPrefix:@"/Library/LaunchDaemons/"]
		|| [path hasPrefix:@"/System/Library/LaunchDaemons/"]
		|| [path hasPrefix:@"/Library/PreferenceBundles"]
		|| [path hasPrefix:@"/Library/PreferenceLoader"]
		|| [path hasPrefix:@"/Library/Switches"]
		// || [path hasPrefix:@"/Library/Themes"]
		|| [path hasPrefix:@"/Library/dpkg"]
		|| [path hasPrefix:@"/jb"]
		|| [path hasPrefix:@"/electra"]
		|| [path hasPrefix:@"/bin"]
		|| [path hasPrefix:@"/sbin"]
		|| [path hasPrefix:@"/var/cache/apt"]
		|| [path hasPrefix:@"/var/lib"]
		|| [path hasPrefix:@"/var/log/"]
		|| [path hasPrefix:@"/var/stash"]
		|| [path hasPrefix:@"/var/db/stash"]
		|| [path hasPrefix:@"/var/mobile/Library/Cydia"]
		|| [path hasPrefix:@"/var/mobile/Library/Logs/Cydia"]
		|| [path hasPrefix:@"/var/mobile/Library/SBSettings"]
		|| [path isEqualToString:@"/var/tmp/cydia.log"]
		|| [path isEqualToString:@"/var/tmp/Cydia.log"]
		|| [path isEqualToString:@"/var/tmp/syslog"]
		|| [path isEqualToString:@"/var/tmp/slide.txt"]
		|| [path isEqualToString:@"/tmp/cydia.log"]
		|| [path isEqualToString:@"/tmp/Cydia.log"]
		|| [path isEqualToString:@"/tmp/syslog"]
		|| [path isEqualToString:@"/tmp/slide.txt"]
		|| [path hasPrefix:@"/private/var/cache/apt"]
		|| [path hasPrefix:@"/private/var/lib"]
		|| [path hasPrefix:@"/private/var/log/"]
		|| [path hasPrefix:@"/private/var/stash"]
		|| [path hasPrefix:@"/private/var/db/stash"]
		|| [path hasPrefix:@"/private/var/mobile/Library/Cydia"]
		|| [path hasPrefix:@"/private/var/mobile/Library/Logs/Cydia"]
		|| [path hasPrefix:@"/private/var/mobile/Library/SBSettings"]
		|| [path isEqualToString:@"/private/var/tmp/cydia.log"]
		|| [path isEqualToString:@"/private/var/tmp/Cydia.log"]
		|| [path isEqualToString:@"/private/var/tmp/syslog"]
		|| [path isEqualToString:@"/private/var/tmp/slide.txt"]
		|| [path isEqualToString:@"/tmp/amfidebilitate.out"]
		|| [path hasPrefix:@"/usr/bin"]
		|| [path hasPrefix:@"/usr/sbin"]
		|| [path hasPrefix:@"/usr/libexec/"]
		|| [path hasPrefix:@"/usr/share/dpkg"]
		|| [path hasPrefix:@"/usr/share/bigboss"]
		|| [path hasPrefix:@"/usr/share/jailbreak"]
		|| [path hasPrefix:@"/usr/share/entitlements"]
		|| [path hasPrefix:@"/usr/lib/"]
		|| [path hasPrefix:@"/usr/include"]
		|| [path hasPrefix:@"/etc/alternatives"]
		|| [path hasPrefix:@"/etc/apt"]
		|| [path hasPrefix:@"/etc/dpkg"]
		|| [path hasPrefix:@"/etc/dropbear"]
		|| [path hasPrefix:@"/etc/ssh"]
		|| [path hasPrefix:@"/User/Library/Cydia"]
		|| [path hasPrefix:@"/User/Library/Logs/Cydia"]
		|| [path hasPrefix:@"/."]
		|| [path hasPrefix:@"/meridian"]
		|| [path hasPrefix:@"/bootstrap"]
		|| [path hasPrefix:@"/panguaxe"]
		|| [path hasPrefix:@"/private/var/mobile/Media/panguaxe"]
		|| [path hasPrefix:@"/taig"]
		|| [path hasPrefix:@"/pguntether"]
	) && (
		![path hasPrefix:@"/usr/lib/log"]
	);
}

bool is_jb_path_c(const char *path) {
	NSString *name = [NSString stringWithUTF8String:path];
	return is_jb_path(name);
}

bool is_path_sb_readonly(NSString *path) {
	return (
		[path hasPrefix:@"/private"]
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

		if(errorPtr != NULL) {
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

		if(error != NULL) {
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

		if(error != NULL) {
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
			NSLog(@"[shadow] allowed access: %s", pathname);
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
			NSLog(@"[shadow] allowed open with path %s", pathname);
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
	NSString *executablePath = [[NSBundle mainBundle] executablePath];

	// Only hook for sandboxed user apps.
	if([executablePath hasPrefix:@"/var/containers/Bundle/Application"]) {
		NSLog(@"[shadow] enabled hooks");
		%init(sandboxed);
	}
}
