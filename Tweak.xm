// Shadow by jjolano
// Simple jailbreak detection blocker tested on iOS 12.1.2 (unc0ver).

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <dlfcn.h>
#include <spawn.h>
#include <errno.h>
#include <pwd.h>

#include "codesign.h"

NSMutableDictionary *jb_map = nil;
NSSet *jb_file_map = nil;
NSMutableArray *dyld_clean_array = nil;
uint32_t dyld_clean_array_count = 0;
BOOL generated_dyld_array = NO;

BOOL standardize_paths = NO;
BOOL use_access_workaround = YES;

bool is_dyld_restricted(NSString *name) {
	return (jb_file_map && [jb_file_map containsObject:name])
	|| ([name hasPrefix:@"/Library/Frameworks"]
	|| [name hasPrefix:@"/Library/Caches"]
	|| [name containsString:@"MobileSubstrate"]
	|| [name containsString:@"substrate"]
	|| [name containsString:@"substitute"]
	|| [name containsString:@"TweakInject"]
	|| [name containsString:@"libjailbreak"]
	|| [name containsString:@"cycript"]
	|| [name containsString:@"SBInject"]
	|| [name containsString:@"pspawn"]
	|| [name containsString:@"applist"]
	|| [name containsString:@"librocketbootstrap"]
	|| [name containsString:@"libcolorpicker"]);
}

void generate_dyld_array(uint32_t count) {
	generated_dyld_array = NO;

	if(dyld_clean_array) {
		[dyld_clean_array removeAllObjects];
	} else {
		dyld_clean_array = [NSMutableArray new];
	}

	dyld_clean_array_count = 0;

	for(uint32_t i = 0; i < count; i++) {
		const char *cname = _dyld_get_image_name(i);

		if(cname) {
			NSString *name = [NSString stringWithUTF8String:cname];

			if(is_dyld_restricted(name)) {
				// Skip adding this to clean dyld array.
				continue;
			}

			// Get other info about this dyld which may be requested.
			const struct mach_header *header = _dyld_get_image_header(i);
			intptr_t slide = _dyld_get_image_vmaddr_slide(i);

			// Add this to clean dyld array.
			[dyld_clean_array addObject:@{
				@"image_index" : [NSNumber numberWithUnsignedInt:i],
				@"name" : name,
				@"header" : [NSData dataWithBytes:header length:sizeof(struct mach_header)],
				@"slide" : [NSValue valueWithPointer:(const void *)slide]
			}];
		}
	}

	dyld_clean_array_count = [dyld_clean_array count];
	generated_dyld_array = YES;
}

void init_jb_map() {
	// TODO: design this map system better to handle exceptions

	NSMutableDictionary *jb_map_etc = [[NSMutableDictionary alloc] init];

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
	[jb_map_etc setValue:@YES forKey:@"/."];

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
	[jb_map_var setValue:@YES forKey:@"/run"];

	NSMutableDictionary *jb_map_library = [[NSMutableDictionary alloc] init];

	[jb_map_library setValue:@YES forKey:@"/MobileSubstrate"];
	[jb_map_library setValue:@YES forKey:@"/substrate"];
	[jb_map_library setValue:@YES forKey:@"/TweakInject"];
	[jb_map_library setValue:@YES forKey:@"/LaunchDaemons"];
	[jb_map_library setValue:@YES forKey:@"/PreferenceBundles"];
	[jb_map_library setValue:@YES forKey:@"/PreferenceLoader"];
	[jb_map_library setValue:@YES forKey:@"/Switches"];
	[jb_map_library setValue:@YES forKey:@"/dpkg"];
	[jb_map_library setValue:@YES forKey:@"/Caches/"];
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
	[jb_map_usr_share setValue:@YES forKey:@"/locale"];

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
	[jb_map setValue:@NO forKey:@"/.file"];
	[jb_map setValue:@YES forKey:@"/System/Library/PreferenceBundles/AppList.bundle"];
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

	if(map == jb_map) {
		if(standardize_paths && [path isAbsolutePath]) {
			path = [path stringByStandardizingPath];
		}

		if(jb_file_map) {
			// Check if this path is in file map.
			if([jb_file_map containsObject:path]) {
				return YES;
			}
		}
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

BOOL is_url_restricted(NSMutableDictionary *map, NSURL *url) {
	if(!map || !url) {
		return NO;
	}

	if([[url scheme] isEqualToString:@"file"]) {
		return is_path_restricted(map, [url path]);
	}

	return NO;
}

%group stable_hooks
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileExistsAtPath with path %@", path);
		#endif

		return NO;
	}

	return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileExistsAtPath with path %@", path);
		#endif

		return NO;
	}

	return %orig;
}
%end

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
	if([[url scheme] isEqualToString:@"cydia"]
	|| [[url scheme] isEqualToString:@"sileo"]
	|| [[url scheme] isEqualToString:@"zbra"]) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked canOpenURL for scheme %@", [url scheme]);
		#endif

		return NO;
	}

	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked canOpenURL for path %@", [url path]);
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

	// workaround for tweaks not loading properly in Substrate
	if(use_access_workaround && [[path pathExtension] isEqualToString:@"plist"] && [path containsString:@"DynamicLibraries/"]) {
		return %orig;
	}

	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked access: %@", path);
		#endif

		errno = ENOENT;
		return -1;
	}

	return %orig;
}

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

	return %orig;
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

		return [dyld_clean_array[image_index][@"name"] UTF8String];
		//return %orig([dyld_clean_array[image_index] unsignedIntValue]);
	}

	// Basic filter.
	const char *ret = %orig;

	if(ret && is_dyld_restricted([NSString stringWithUTF8String:ret])) {
		return %orig(0);
	}

	return ret;
}
/*
%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
	if(generated_dyld_array) {
		// Use generated dyld array.
		if(image_index >= dyld_clean_array_count) {
			return NULL;
		}

		static struct mach_header header;
		[dyld_clean_array[image_index][@"header"] getBytes:&header length:sizeof(struct mach_header)];

		return &header;
	}

	return %orig;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
	if(generated_dyld_array) {
		// Use generated dyld array.
		if(image_index >= dyld_clean_array_count) {
			return 0;
		}

		return (intptr_t) [dyld_clean_array[image_index][@"slide"] pointerValue];
	}

	return %orig;
}
*/
%end

%group private_methods
%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
	int ret = %orig;

	if(ops == CS_OPS_STATUS && (ret & CS_PLATFORM_BINARY) && pid == getpid()) {
		// Ensure that the platform binary flag is not set.
		#ifdef DEBUG
		NSLog(@"[shadow] csops (private) - removed platform binary flag");
		#endif

		ret &= ~CS_PLATFORM_BINARY;
	}

	return ret;
}
%end

%group sandboxed_methods
%hookf(pid_t, fork) {
	#ifdef DEBUG
	NSLog(@"[shadow] blocked fork()");
	#endif
	
	errno = ENOSYS;
	return -1;
}

%hookf(FILE *, popen, const char *command, const char *type) {
	#ifdef DEBUG
	NSLog(@"[shadow] blocked popen()");
	#endif

	errno = ENOSYS;
	return NULL;
}

%hookf(int, setgid, gid_t gid) {
	// Block setgid for root.
	if(gid == 0) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked setgid(0)");
		#endif

		errno = EPERM;
		return -1;
	}

	return %orig;
}

%hookf(int, setuid, uid_t uid) {
	// Block setuid for root.
	if(uid == 0) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked setuid(0)");
		#endif

		errno = EPERM;
		return -1;
	}

	return %orig;
}

%hookf(int, setegid, gid_t gid) {
	// Block setegid for root.
	if(gid == 0) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked setegid(0)");
		#endif

		errno = EPERM;
		return -1;
	}

	return %orig;
}

%hookf(int, seteuid, uid_t uid) {
	// Block seteuid for root.
	if(uid == 0) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked seteuid(0)");
		#endif

		errno = EPERM;
		return -1;
	}

	return %orig;
}

%hookf(uid_t, getuid) {
	// Return uid for mobile.
	struct passwd *pw = getpwnam("mobile");
	return pw ? pw->pw_uid : 501;
}

%hookf(gid_t, getgid) {
	// Return gid for mobile.
	struct passwd *pw = getpwnam("mobile");
	return pw ? pw->pw_gid : 501;
}

%hookf(uid_t, geteuid) {
	// Return uid for mobile.
	struct passwd *pw = getpwnam("mobile");
	return pw ? pw->pw_uid : 501;
}

%hookf(uid_t, getegid) {
	// Return gid for mobile.
	struct passwd *pw = getpwnam("mobile");
	return pw ? pw->pw_gid : 501;
}

%hookf(int, setreuid, uid_t ruid, uid_t euid) {
	// Block for root.
	if(ruid == 0 || euid == 0) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked setreuid");
		#endif

		errno = EPERM;
		return -1;
	}

	return %orig;
}

%hookf(int, setregid, gid_t rgid, gid_t egid) {
	// Block for root.
	if(rgid == 0 || egid == 0) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked setregid");
		#endif

		errno = EPERM;
		return -1;
	}

	return %orig;
}
%end

%group experimental_hooks
%hook NSBundle
- (id)objectForInfoDictionaryKey:(NSString *)key {
	if([key isEqualToString:@"SignerIdentity"]) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked objectForInfoDictionaryKey (SignerIdentity)");
		#endif

		return nil;
	}

	return %orig;
}
%end

%hook NSFileManager
- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked contentsOfDirectoryAtURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}
	
	/*
	if(jb_file_map && [[url scheme] isEqualToString:@"file"]) {
		if([jb_file_map containsObject:[url path]]) {
			#ifdef DEBUG
			NSLog(@"[shadow] blocked contentsOfDirectoryAtURL for path %@", [url path]);
			#endif

			if(error) {
				*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
			}

			return nil;
		}
	}
	*/

	NSArray *ret = %orig;

	if(ret && jb_file_map) {
		NSMutableArray *newret = [NSMutableArray new];

		// Filter the array.
		for(NSURL *content_url in ret) {
			if(![jb_file_map containsObject:[content_url path]]) {
				[newret addObject:content_url];
			} else {
				#ifdef DEBUG
				NSLog(@"[shadow] filtered contentsOfDirectoryAtURL for path %@", [content_url path]);
				#endif
			}
		}

		return newret;
	}

	return ret;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked contentsOfDirectoryAtPath for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	/*
	if(jb_file_map) {
		if([jb_file_map containsObject:path]) {
			#ifdef DEBUG
			NSLog(@"[shadow] blocked contentsOfDirectoryAtPath for path %@", path);
			#endif

			if(error) {
				*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
			}

			return nil;
		}
	}
	*/

	NSArray *ret = %orig;

	if(ret && jb_file_map) {
		NSMutableArray *newret = [NSMutableArray new];

		// Filter the array.
		for(NSString *content_path in ret) {
			if(![jb_file_map containsObject:content_path]) {
				[newret addObject:content_path];
			} else {
				#ifdef DEBUG
				NSLog(@"[shadow] filtered contentsOfDirectoryAtPath for path %@", content_path);
				#endif
			}
		}

		return newret;
	}

	return ret;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked enumeratorAtURL for path %@", [url path]);
		#endif

		return %orig([NSURL fileURLWithPath:@"file:///.file"], keys, mask, handler);
	}

	return %orig;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked enumeratorAtPath for path %@", path);
		#endif

		return %orig(@"/.file");
	}

	return %orig;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked subpathsOfDirectoryAtPath for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	NSArray *ret = %orig;

	if(ret && jb_file_map) {
		NSMutableArray *newret = [NSMutableArray new];

		// Filter the array.
		for(NSString *content_path in ret) {
			if(![jb_file_map containsObject:content_path]) {
				[newret addObject:content_path];
			} else {
				#ifdef DEBUG
				NSLog(@"[shadow] filtered subpathsOfDirectoryAtPath for path %@", content_path);
				#endif
			}
		}

		return newret;
	}

	return ret;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked subpathsAtPath for path %@", path);
		#endif

		return nil;
	}

	NSArray *ret = %orig;

	if(ret && jb_file_map) {
		NSMutableArray *newret = [NSMutableArray new];

		// Filter the array.
		for(NSString *content_path in ret) {
			if(![jb_file_map containsObject:content_path]) {
				[newret addObject:content_path];
			} else {
				#ifdef DEBUG
				NSLog(@"[shadow] filtered subpathsAtPath for path %@", content_path);
				#endif
			}
		}

		return newret;
	}

	return ret;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, srcURL)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked copyItemAtURL for path %@", [srcURL path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, srcPath)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked copyItemAtPath for path %@", srcPath);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked componentsToDisplayForPath for path %@", path);
		#endif

		return nil;
	}

	return %orig;
}

- (NSString *)displayNameAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked displayNameAtPath for path %@", path);
		#endif

		return path;
	}

	return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked attributesOfItemAtPath for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (NSData *)contentsAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked contentsAtPath for path %@", path);
		#endif

		return nil;
	}

	return %orig;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
	if(is_path_restricted(jb_map, path1) || is_path_restricted(jb_map, path2)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked contentsEqualAtPath for paths %@ | %@", path1, path2);
		#endif

		return NO;
	}

	return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectoryAtURL:(NSURL *)directoryURL toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, directoryURL) || is_url_restricted(jb_map, otherURL)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked getRelationship for paths %@ | %@", [directoryURL path], [otherURL path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, otherURL)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked getRelationship for path %@", [otherURL path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)changeCurrentDirectoryPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked changeCurrentDirectoryPath for path %@", path);
		#endif

		return NO;
	}

	return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked isReadableFileAtPath with path %@", path);
		#endif

		return NO;
	}

	return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked isWritableFileAtPath with path %@", path);
		#endif

		return NO;
	}

	return %orig;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked isDeletableFileAtPath with path %@", path);
		#endif

		return NO;
	}

	return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked isExecutableFileAtPath with path %@", path);
		#endif

		return NO;
	}

	return %orig;
}

- (BOOL)createSymbolicLinkAtURL:(NSURL *)url withDestinationURL:(NSURL *)destURL error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, destURL)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked createSymbolicLinkAtURL for path %@ -> %@", [url path], [destURL path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path withDestinationPath:(NSString *)destPath error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, destPath)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked createSymbolicLinkAtPath for path %@ -> %@", path, destPath);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)linkItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, dstURL)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked linkItemAtURL for path %@ -> %@", [srcURL path], [dstURL path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, dstPath)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked linkItemAtPath for path %@ -> %@", srcPath, dstPath);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return NO;
	}

	return %orig;
}

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked destinationOfSymbolicLinkAtPath for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}
%end

%hook NSFileHandle
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileHandleForReadingAtPath for path %@", path);
		#endif

		return nil;
	}

	return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileHandleForReadingFromURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileHandleForWritingAtPath for path %@", path);
		#endif

		return nil;
	}

	return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileHandleForWritingToURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileHandleForUpdatingAtPath for path %@", path);
		#endif

		return nil;
	}

	return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fileHandleForUpdatingURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}
%end

%hook NSString
+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked stringWithContentsOfFile for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfFile for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked stringWithContentsOfFile for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfFile for path %@", path);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

+ (instancetype)stringWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked stringWithContentsOfURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

+ (instancetype)stringWithContentsOfURL:(NSURL *)url usedEncoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked stringWithContentsOfURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url usedEncoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfURL for path %@", [url path]);
		#endif

		if(error) {
			*error = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}
%end

%hook NSData
+ (instancetype)dataWithContentsOfFile:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked dataWithContentsOfFile for path %@", path);
		#endif

		return nil;
	}

	return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked dataWithContentsOfFile for path %@", path);
		#endif

		if(errorPtr) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked dataWithContentsOfURL for path %@", [url path]);
		#endif

		return nil;
	}

	return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked dataWithContentsOfURL for path %@", [url path]);
		#endif

		if(errorPtr) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfFile for path %@", path);
		#endif

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfFile for path %@", path);
		#endif

		if(errorPtr) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfURL for path %@", [url path]);
		#endif

		return nil;
	}

	return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)errorPtr {
	if(is_url_restricted(jb_map, url)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked initWithContentsOfURL for path %@", [url path]);
		#endif

		if(errorPtr) {
			*errorPtr = [NSError errorWithDomain:@"NSCocoaErrorDomain" code:NSFileNoSuchFileError userInfo:nil];
		}

		return nil;
	}

	return %orig;
}
%end

%hookf(int, posix_spawn, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
	if(!pathname) {
		return %orig;
	}

	NSString *path = [NSString stringWithUTF8String:pathname];

	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked posix_spawn");
		#endif

		return ENOSYS;
	}

	return %orig;
}

%hookf(int, posix_spawnp, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
	if(!pathname) {
		return %orig;
	}

	NSString *path = [NSString stringWithUTF8String:pathname];

	if(is_path_restricted(jb_map, path)) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked posix_spawnp");
		#endif

		return ENOSYS;
	}

	return %orig;
}

%hookf(char *, realpath, const char *pathname, char *resolved_path) {
	if(!pathname) {
		return %orig;
	}

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:pathname])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked realpath for path %s", pathname);
		#endif

		errno = ENOENT;
		return NULL;
	}

	return %orig;
}

%hookf(int, symlink, const char *path1, const char *path2) {
	if(!path1 || !path2) {
		return %orig;
	}

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:path2])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked symlink for path %s -> %s", path1, path2);
		#endif

		errno = ENOENT;
		return -1;
	}

	return %orig;
}

%hookf(int, link, const char *path1, const char *path2) {
	if(!path1 || !path2) {
		return %orig;
	}

	if(is_path_restricted(jb_map, [NSString stringWithUTF8String:path2])) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked link for path %s -> %s", path1, path2);
		#endif

		errno = ENOENT;
		return -1;
	}

	return %orig;
}

%hookf(int, fstatat, int fd, const char *pathname, struct stat *buf, int flag) {
	if(!pathname) {
		return %orig;
	}

	BOOL restricted = NO;
	char cfdpath[PATH_MAX];
	
	if(fcntl(fd, F_GETPATH, cfdpath) != -1) {
		NSString *fdpath = [NSString stringWithUTF8String:cfdpath];
		NSString *path = [NSString stringWithUTF8String:pathname];

		restricted = is_path_restricted(jb_map, fdpath);

		if(!restricted && [fdpath isEqualToString:@"/"]) {
			restricted = is_path_restricted(jb_map, [NSString stringWithFormat:@"/%@", path]);
		}
	}

	if(restricted) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked fstatat with path %s", pathname);
		#endif

		errno = ENOENT;
		return -1;
	}

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
			if(buf) {
				#ifdef DEBUG
				NSLog(@"[shadow] filtered statfs on %s", path);
				#endif

				// Ensure root is marked read-only.
				buf->f_flags |= MNT_RDONLY;
				return ret;
			}
		}

		if(is_path_restricted(jb_map, pathname)) {
			#ifdef DEBUG
			NSLog(@"[shadow] blocked statfs on %s", path);
			#endif

			errno = ENOENT;
			return -1;
		}
	}

	return ret;
}
%end

%group dlsym_hook
%hookf(void *, dlsym, void *handle, const char *symbol) {
	if(!symbol) {
		return NULL;
	}

	NSString *sym = [NSString stringWithUTF8String:symbol];

	if([sym hasPrefix:@"MS"]
	|| [sym hasPrefix:@"Sub"]
	|| [sym hasPrefix:@"substitute_"]) {
		#ifdef DEBUG
		NSLog(@"[shadow] blocked dlsym for symbol %@", sym);
		#endif

		return NULL;
	}

	void *ret = %orig;
	return ret;
}
%end

%group hook_debugging
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
	int ret = %orig;

	if(ret == 0
	&& name[0] == CTL_KERN
	&& name[1] == KERN_PROC
	&& name[2] == KERN_PROC_PID
	&& name[3] == getpid()) {
		// Remove trace flag.
		if(oldp) {
			struct kinfo_proc *p = ((struct kinfo_proc *) oldp);

			if(p->kp_proc.p_flag & P_TRACED) {
				p->kp_proc.p_flag &= ~P_TRACED;

				#ifdef DEBUG
				NSLog(@"[shadow] sysctl: removed trace flag");
				#endif
			}
		}
	}

	return ret;
}

%hookf(pid_t, getppid) {
	#ifdef DEBUG
	NSLog(@"[shadow] spoofed getppid");
	#endif

	return 1;
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

			// Specify default preferences
			BOOL prefs_enabled = YES;
			BOOL prefs_exclude_system_apps = YES;
			NSString *prefs_mode = @"blacklist";
			BOOL prefs_private_methods = NO;
			BOOL prefs_experimental_hooks = NO;
			BOOL prefs_dlsym_hook = NO;
			BOOL prefs_dyld_array_enabled = NO;
			BOOL prefs_bundleid_enabled = NO;
			BOOL prefs_hook_debugging = NO;
			BOOL prefs_hook_sandboxed = NO;

			// Load preference file
			NSMutableDictionary *prefs = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
			
			if(prefs) {
				if(prefs[@"enabled"]) {
					prefs_enabled = [prefs[@"enabled"] boolValue];
				}

				if(prefs[@"exclude_system_apps"]) {
					prefs_exclude_system_apps = [prefs[@"exclude_system_apps"] boolValue];
				}

				if(prefs[@"mode"]) {
					prefs_mode = prefs[@"mode"];
				}

				if(prefs[@"private_methods"]) {
					prefs_private_methods = [prefs[@"private_methods"] boolValue];
				}

				if(prefs[@"hook_debugging"]) {
					prefs_hook_debugging = [prefs[@"hook_debugging"] boolValue];
				}

				if(prefs[@"experimental_hooks"]) {
					prefs_experimental_hooks = [prefs[@"experimental_hooks"] boolValue];
				}

				if(prefs[@"standardize_path"]) {
					standardize_paths = [prefs[@"standardize_path"] boolValue];
				}

				if(prefs[@"hook_sandboxed"]) {
					prefs_hook_sandboxed = [prefs[@"hook_sandboxed"] boolValue];
				}

				if(prefs[@"workaround_access"]) {
					use_access_workaround = [prefs[@"workaround_access"] boolValue];
				}

				if(prefs[@"dyld_array_enabled"]) {
					prefs_dyld_array_enabled = [prefs[@"dyld_array_enabled"] boolValue];
				}

				if(prefs[bundleIdentifier]) {
					prefs_bundleid_enabled = [prefs[bundleIdentifier] boolValue];
				}
			}

			NSMutableDictionary *prefs_dlsym = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/me.jjolano.shadow.dlsym.plist"];

			if(prefs_dlsym) {
				if(prefs_dlsym[bundleIdentifier]) {
					prefs_dlsym_hook = [prefs_dlsym[bundleIdentifier] boolValue];
				}
			}

			if(!prefs_enabled) {
				// Shadow disabled in preferences.
				return;
			}

			if(prefs_exclude_system_apps) {
				// Disable Shadow for Apple and jailbreak apps
				NSArray *excluded_bundleids = @[
					@"com.apple", // Apple apps
					@"is.workflow.my.app", // Shortcuts
					@"science.xnu.undecimus", // unc0ver
					@"com.electrateam.chimera", // Chimera
					@"org.coolstar.electra" // Electra
				];

				for(NSString *bundle_id in excluded_bundleids) {
					if([bundleIdentifier hasPrefix:bundle_id]) {
						return;
					}
				}
			}

			#ifdef DEBUG
			NSLog(@"[shadow] using %@ mode", prefs_mode);
			#endif

			if([prefs_mode isEqualToString:@"whitelist"]) {
				// Whitelist mode - activate hooks only for enabled bundleids
				if(!prefs_bundleid_enabled) {
					// App is not whitelisted in preferences
					return;
				}
			} else {
				// Blacklist mode - disable hooks for enabled bundleids
				if(prefs_bundleid_enabled) {
					// App is blacklisted in preferences
					return;
				}
			}

			if(prefs_dyld_array_enabled) {
				// Generate clean dyld array.
				uint32_t dyld_orig_count = _dyld_image_count();
				generate_dyld_array(dyld_orig_count);

				#ifdef DEBUG
				NSLog(@"[shadow] generated clean dyld array (%d/%d)", dyld_clean_array_count, dyld_orig_count);
				#endif
			}

			NSMutableDictionary *prefs_map = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/me.jjolano.shadow.map.plist"];

			if(prefs_map && prefs_map[@"blacklist"]) {
				if(prefs_map[bundleIdentifier] && [prefs_map[bundleIdentifier] boolValue]) {
					jb_file_map = [NSSet setWithArray:prefs_map[@"blacklist"]];

					#ifdef DEBUG
					NSLog(@"[shadow] loaded file map (%lu files)", (unsigned long) [jb_file_map count]);
					#endif
				}
			}

			// Allocate and initialize restricted paths map.
			init_jb_map();

			#ifdef DEBUG
			NSLog(@"[shadow] initialized restricted paths map");
			#endif

			// Hook bypass methods.
			%init(stable_hooks);

			#ifdef DEBUG
			NSLog(@"[shadow] hooked basic detection methods");
			#endif

			if(prefs_private_methods) {
				%init(private_methods);

				#ifdef DEBUG
				NSLog(@"[shadow] hooked private methods");
				#endif
			}

			if(prefs_hook_sandboxed) {
				%init(sandboxed_methods);

				#ifdef DEBUG
				NSLog(@"[shadow] hooked sandboxed methods");
				#endif
			}

			if(prefs_hook_debugging) {
				%init(hook_debugging);

				#ifdef DEBUG
				NSLog(@"[shadow] hooked debugging checks");
				#endif
			}

			if(prefs_experimental_hooks) {
				%init(experimental_hooks);

				#ifdef DEBUG
				NSLog(@"[shadow] hooked experimental methods");
				#endif
			}

			if(prefs_dlsym_hook) {
				%init(dlsym_hook);

				#ifdef DEBUG
				NSLog(@"[shadow] hooked dlsym");
				#endif
			}
		}
	}
}
