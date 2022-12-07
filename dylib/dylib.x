#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "../api/Shadow.h"
#import "../api/ShadowService.h"
#import "hooks/hooks.h"

#import <libSandy.h>
#import <Cephei/HBPreferences.h>

#ifndef kCFCoreFoundationVersionNumber_iOS_11_0
#define kCFCoreFoundationVersionNumber_iOS_11_0 1443.00
#endif

Shadow* _shadow = nil;
ShadowService* _srv = nil;
NSUserDefaults* prefs = nil;

%group hook_springboard
%hook SpringBoard
- (void)applicationDidFinishLaunching:(UIApplication *)application {
    %orig;

	// Check if we are in a rootless environment.
	NSDictionary* jb_attr = [[NSFileManager defaultManager] attributesOfItemAtPath:@"/var/jb" error:nil];
	BOOL rootless = [jb_attr[NSFileType] isEqualToString:NSFileTypeSymbolicLink];

	_srv = [ShadowService new];
	[_srv setRootless:rootless];

	[_srv startService];
	NSLog(@"%@", @"started ShadowService");

	NSDictionary* db = [_srv generateDatabase];

	// Save this database to filesystem
	if(db) {
		BOOL success;

		if(rootless) {
			success = [db writeToFile:@("/var/jb" LOCAL_SERVICE_DB) atomically:NO];
		} else {
			success = [db writeToFile:@LOCAL_SERVICE_DB atomically:NO];
		}

		if(success) {
			NSLog(@"%@", @"successfully saved generated db");
		} else {
			NSLog(@"%@", @"failed to save generate db");
		}
	}
}
%end
%end

%ctor {
	// Determine the application we're injected into.
	NSString* bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
	NSString* executablePath = [[NSBundle mainBundle] executablePath];
	NSString* bundlePath = [[NSBundle mainBundle] bundlePath];

	// Injected into SpringBoard.
	if([bundleIdentifier isEqualToString:@"com.apple.springboard"] || [[executablePath lastPathComponent] isEqualToString:@"SpringBoard"]) {
		%init(hook_springboard);
		NSLog(@"%@", @"loaded into SpringBoard");
		return;
	}

	// Only load Shadow for sandboxed applications.
	// Don't load for App Extensions (.. unless developers are adding detection in those too :/)
	if(![[NSBundle mainBundle] appStoreReceiptURL]
	|| [executablePath hasPrefix:@"/Applications"]
	|| [executablePath hasPrefix:@"/System"]
	|| ![bundlePath hasSuffix:@".app"]) {
		return;
	}

	// Load preferences.
	if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0) {
		if(libSandy_applyProfile("ShadowSettings") != kLibSandySuccess) {
			NSLog(@"%@", @"failed to apply libsandy ShadowSettings profile");
		}

		prefs = [ShadowService getPreferences];

		NSLog(@"%@", @"loaded preferences with libsandy");
	} else {
		// Use Cephei to load preferences.
		HBPreferences* cepheiPrefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];

		prefs = (NSUserDefaults *) cepheiPrefs;
		[prefs registerDefaults:[ShadowService getDefaultPreferences]];

		NSLog(@"%@", @"loaded preferences with cephei");
	}

	if(!prefs) {
		NSLog(@"%@", @"failed to load preferences");
	}

	BOOL enabled = NO;

	// Determine whether to load the rest of the tweak.
	// Load app-specific settings, if enabled.
	NSDictionary* prefs_load = nil;
	NSDictionary* prefs_app = [prefs objectForKey:bundleIdentifier];

	if(prefs_app && prefs_app[@"App_Override"] && [prefs_app[@"App_Override"] boolValue]) {
		enabled = prefs_app[@"App_Enabled"] && [prefs_app[@"App_Enabled"] boolValue];
		prefs_load = prefs_app;
	}

	if(!prefs_load) {
		enabled = [prefs boolForKey:@"Global_Enabled"];
		prefs_load = @{
			@"Tweak_CompatEx" : @([prefs boolForKey:@"Tweak_CompatEx"]),
			@"Use_Service" : @([prefs boolForKey:@"Use_Service"]),
			@"Hook_Filesystem" : @([prefs boolForKey:@"Hook_Filesystem"]),
			@"Hook_DynamicLibraries" : @([prefs boolForKey:@"Hook_DynamicLibraries"]),
			@"Hook_URLScheme" : @([prefs boolForKey:@"Hook_URLScheme"]),
			@"Hook_EnvVars" : @([prefs boolForKey:@"Hook_EnvVars"]),
			@"Hook_FilesystemExtra" : @([prefs boolForKey:@"Hook_FilesystemExtra"]),
			@"Hook_Foundation" : @([prefs boolForKey:@"Hook_Foundation"]),
			@"Hook_DeviceCheck" : @([prefs boolForKey:@"Hook_DeviceCheck"]),
			@"Hook_MachBootstrap" : @([prefs boolForKey:@"Hook_MachBootstrap"]),
			@"Hook_SymLookup" : @([prefs boolForKey:@"Hook_SymLookup"]),
			@"Hook_LowLevelC" : @([prefs boolForKey:@"Hook_LowLevelC"]),
			@"Hook_AntiDebugging" : @([prefs boolForKey:@"Hook_AntiDebugging"]),
			@"Hook_DynamicLibrariesExtra" : @([prefs boolForKey:@"Hook_DynamicLibrariesExtra"]),
			@"Hook_ObjCRuntime" : @([prefs boolForKey:@"Hook_ObjCRuntime"]),
			@"Hook_FakeMac" : @([prefs boolForKey:@"Hook_FakeMac"]),
			@"Hook_Syscall" : @([prefs boolForKey:@"Hook_Syscall"]),
			@"Hook_Sandbox" : @([prefs boolForKey:@"Hook_Sandbox"])
		};
	}

	if(!enabled) {
		return;
	}

	NSLog(@"%@", @"tweak loaded in app");

	// Check if we are in a rootless environment.
	NSDictionary* jb_attr = [[NSFileManager defaultManager] attributesOfItemAtPath:@"/var/jb" error:nil];
	BOOL rootless = [jb_attr[NSFileType] isEqualToString:NSFileTypeSymbolicLink];

	// Initialize Shadow class.
	_srv = [ShadowService new];
	[_srv setRootless:rootless];

	[_srv startLocalService];

	if([prefs boolForKey:@"Use_Service"]) {
		if(libSandy_applyProfile("ShadowService") != kLibSandySuccess) {
			NSLog(@"%@", @"failed to apply libsandy ShadowService profile");
		}

		[_srv connectService];
	}

	_shadow = [Shadow shadowWithService:_srv];

	if(prefs_load[@"Tweak_CompatEx"]) {
		[_shadow setTweakCompatibility:[prefs_load[@"Tweak_CompatEx"] boolValue]];
	}

	// Initialize hooks.
	NSLog(@"%@", @"starting hooks");

	if(prefs_load[@"Hook_Filesystem"] && [prefs_load[@"Hook_Filesystem"] boolValue]) {
		NSLog(@"%@", @"+ filesystem");

		shadowhook_libc();
		shadowhook_NSFileManager();
	}

	if(prefs_load[@"Hook_DynamicLibraries"] && [prefs_load[@"Hook_DynamicLibraries"] boolValue]) {
		NSLog(@"%@", @"+ dylib");

		// Register before hooking
		_dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
		_dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);
		_dyld_register_func_for_add_image(shadowhook_dyld_shdw_add_image);
		_dyld_register_func_for_remove_image(shadowhook_dyld_shdw_remove_image);

		shadowhook_dyld();
	}

	if(prefs_load[@"Hook_DynamicLibrariesExtra"] && [prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue]) {
		NSLog(@"%@", @"+ dylibex");

		shadowhook_dyld_extra();
	}

	if(prefs_load[@"Hook_URLScheme"] && [prefs_load[@"Hook_URLScheme"] boolValue]) {
		NSLog(@"%@", @"+ urlscheme");

		shadowhook_UIApplication();
	}

	if(prefs_load[@"Hook_EnvVars"] && [prefs_load[@"Hook_EnvVars"] boolValue]) {
		NSLog(@"%@", @"+ envvars");

		shadowhook_libc_envvar();
		shadowhook_NSProcessInfo();
	}

	if(prefs_load[@"Hook_FilesystemExtra"] && [prefs_load[@"Hook_FilesystemExtra"] boolValue]) {
		NSLog(@"%@", @"+ filesystemex");

		shadowhook_libc_extra();
		shadowhook_NSFileHandle();
		shadowhook_NSFileVersion();
		shadowhook_NSFileWrapper();
	}

	if(prefs_load[@"Hook_Foundation"] && [prefs_load[@"Hook_Foundation"] boolValue]) {
		NSLog(@"%@", @"+ foundation");

		shadowhook_NSArray();
		shadowhook_NSDictionary();
		shadowhook_NSBundle();
		shadowhook_NSString();
		shadowhook_NSURL();
		shadowhook_NSData();
		shadowhook_UIImage();
	}

	if(prefs_load[@"Hook_DeviceCheck"] && [prefs_load[@"Hook_DeviceCheck"] boolValue]) {
		NSLog(@"%@", @"+ devicecheck");

		shadowhook_DeviceCheck();
	}

	if(prefs_load[@"Hook_MachBootstrap"] && [prefs_load[@"Hook_MachBootstrap"] boolValue]) {
		NSLog(@"%@", @"+ mach");

		shadowhook_mach();
	}

	if(prefs_load[@"Hook_SymLookup"] && [prefs_load[@"Hook_SymLookup"] boolValue]) {
		NSLog(@"%@", @"+ dlsym");

		shadowhook_dyld_symlookup();
	}

	if(prefs_load[@"Hook_LowLevelC"] && [prefs_load[@"Hook_LowLevelC"] boolValue]) {
		NSLog(@"%@", @"+ llc");

		shadowhook_libc_lowlevel();
	}

	if(prefs_load[@"Hook_AntiDebugging"] && [prefs_load[@"Hook_AntiDebugging"] boolValue]) {
		NSLog(@"%@", @"+ debug");

		shadowhook_libc_antidebugging();
	}

	if(prefs_load[@"Hook_ObjCRuntime"] && [prefs_load[@"Hook_ObjCRuntime"] boolValue]) {
		NSLog(@"%@", @"+ objc");

		shadowhook_objc();
	}

	if(prefs_load[@"Hook_FakeMac"] && [prefs_load[@"Hook_FakeMac"] boolValue]) {
		NSLog(@"%@", @"+ m1");

		shadowhook_NSProcessInfo_fakemac();
	}

	if(prefs_load[@"Hook_Syscall"] && [prefs_load[@"Hook_Syscall"] boolValue]) {
		NSLog(@"%@", @"+ syscall");

		shadowhook_syscall();
	}

	if(prefs_load[@"Hook_Sandbox"] && [prefs_load[@"Hook_Sandbox"] boolValue]) {
		NSLog(@"%@", @"+ sandbox");

		shadowhook_sandbox();
	}

	NSLog(@"%@", @"completed hooks");
}
