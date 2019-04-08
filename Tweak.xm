// Shadow by jjolano
// Simple jailbreak detection blocker tested on iOS 12.1.2.

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

%group sandboxed

bool is_jb_path(NSString *path) {
	return (
		[path hasPrefix:@"/Applications"]
		|| [path hasPrefix:@"/Library/MobileSubstrate"]
		|| [path hasPrefix:@"/Library/substrate"]
		|| [path hasPrefix:@"/Library/TweakInject"]
		|| [path hasPrefix:@"/System/Library/LaunchDaemons"]
		|| [path hasPrefix:@"/jb"]
		|| [path hasPrefix:@"/electra"]
		|| [path hasPrefix:@"/bin"]
		|| [path hasPrefix:@"/var/cache"]
		|| [path hasPrefix:@"/var/lib"]
		|| [path hasPrefix:@"/var/log"]
		|| [path hasPrefix:@"/var/tmp"]
		|| [path hasPrefix:@"/usr/sbin"]
		|| [path hasPrefix:@"/usr/libexec"]
		|| [path hasPrefix:@"/etc"]
		|| [path hasPrefix:@"/private/var/cache"]
		|| [path hasPrefix:@"/private/var/lib"]
		|| [path hasPrefix:@"/private/var/log"]
		|| [path hasPrefix:@"/private/var/tmp"]
		|| [path hasPrefix:@"/."]
	);
}

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
	if(is_jb_path(path)) {
		return NO;
	}

	return %orig;
}
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
	if([[url scheme] isEqualToString:@"cydia"]
	|| [[url scheme] isEqualToString:@"sileo"]) {
		return NO;
	}

	return %orig;
}
%end

/*
// Seems to be disabled in the SDK. Probably no point hooking this.
%hookf(int, "system", const char *command) {
	if(command == NULL) {
		return 0;
	}

	return %orig;
}
*/

%hookf(pid_t, fork) {
	return -1;
}

%hookf(char *, getenv, const char *name) {
	if(strcmp(name, "DYLD_INSERT_LIBRARIES") == 0
	|| strcmp(name, "_MSSafeMode") == 0) {
		return NULL;
	}

	return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
	NSString *path = [NSString stringWithUTF8String: pathname];

	if(is_jb_path(path)) {
		return NULL;
	}

	return %orig;
}
/*
// This hook seems to cause problems? Maybe it's used by Substrate itself.
%hookf(int, open, const char *pathname, int flags) {
	NSString *path = [NSString stringWithUTF8String: pathname];

	if(is_jb_path(path)) {
		return -1;
	}

	return %orig;
}
*/
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

	NSString *path = [NSString stringWithUTF8String: pathname];

	if(is_jb_path(path)) {
		return -1;
	}

	int ret = %orig;

	if(ret == 0 && strcmp(pathname, "/") == 0) {
		// Ensure root is not seen as writable.
		statbuf->st_mode &= ~S_IWUSR;
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
		return stat(pathname, statbuf);
	}

	NSString *path = [NSString stringWithUTF8String: pathname];

	if(is_jb_path(path)) {
		return -1;
	}

	int ret = %orig;

	if(ret == 0 && strcmp(pathname, "/") == 0) {
		// Ensure root is not seen as writable.
		statbuf->st_mode &= ~S_IWUSR;
	}

	return ret;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
	const char *ret = %orig;

	if(ret != NULL) {
		NSString *image_name = [NSString stringWithUTF8String: ret];

		if([image_name rangeOfString:@"MobileSubstrate"].location != NSNotFound
		|| [image_name rangeOfString:@"substrate"].location != NSNotFound
		|| [image_name rangeOfString:@"TweakInject"].location != NSNotFound) {
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
		%init(sandboxed);
	}
}
