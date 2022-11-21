#import <HBLog.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Cephei/HBPreferences.h>

#import "../api/Shadow.h"
#import "../api/ShadowService.h"
#import "hooks/hooks.h"

Shadow* _shadow = nil;
ShadowService* _srv = nil;

%group hook_springboard
%hook SpringBoard
- (void)applicationDidFinishLaunching:(UIApplication *)application {
    %orig;

	[_srv startService];
}
%end
%end

%ctor {
	// Load preferences.
	HBPreferences* prefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];

	// Register default preferences.
	[prefs registerDefaults:@{
		@"Global_Enabled" : @(NO),
		@"Hook_Filesystem" : @(YES),
		@"Hook_DynamicLibraries" : @(YES),
		@"Hook_URLScheme" : @(YES),
		@"Hook_EnvVars" : @(YES),
		@"Hook_FilesystemExtra" : @(NO),
		@"Hook_Foundation" : @(NO),
		@"Hook_DeviceCheck" : @(YES),
		@"Hook_MachBootstrap" : @(NO),
		@"Hook_SymLookup" : @(NO),
		@"Hook_LowLevelC" : @(NO),
		@"Hook_AntiDebugging" : @(NO),
		@"Hook_DynamicLibrariesExtra" : @(NO),
		@"Hook_ObjCRuntime" : @(NO),
		@"Hook_FakeMac" : @(NO),
		@"Tweak_Compat" : @(YES),
		@"Tweak_CompatEx" : @(NO),
		@"Hook_Syscall" : @(NO),
		@"Hook_Sandbox" : @(NO)
	}];

	// Determine the application we're injected into.
	NSString* bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
	NSString* executablePath = [[NSBundle mainBundle] executablePath];
	NSString* bundlePath = [[NSBundle mainBundle] bundlePath];

	// Injected into SpringBoard.
	if([bundleIdentifier isEqualToString:@"com.apple.springboard"] || [[executablePath lastPathComponent] isEqualToString:@"SpringBoard"]) {
		_srv = [ShadowService new];

		%init(hook_springboard);
		HBLogDebug(@"%@", @"loaded into SpringBoard");
		return;
	}

	// Only load Shadow for sandboxed applications.
	// Don't load for App Extensions (.. unless developers are adding detection in those too :/)
	if(![[NSBundle mainBundle] appStoreReceiptURL]
	|| [executablePath hasPrefix:@"/Applications"]
	|| [executablePath hasPrefix:@"/System"]
	|| [bundlePath hasSuffix:@".appex"]) {
		return;
	}

	BOOL enabled = NO;

	// Determine whether to load the rest of the tweak.
	// Load app-specific settings, if enabled.
	NSDictionary* prefs_load = nil;
	NSDictionary* prefs_app = prefs[bundleIdentifier];

	if(prefs_app && prefs_app[@"App_Override"] && [prefs_app[@"App_Override"] boolValue]) {
		enabled = prefs_app[@"App_Enabled"] ? [prefs_app[@"App_Enabled"] boolValue] : NO;
		prefs_load = prefs_app;
	}

	if(!prefs_load) {
		enabled = [prefs[@"Global_Enabled"] boolValue];
		prefs_load = @{
			@"Hook_Filesystem" : prefs[@"Hook_Filesystem"],
			@"Hook_DynamicLibraries" : prefs[@"Hook_DynamicLibraries"],
			@"Hook_URLScheme" : prefs[@"Hook_URLScheme"],
			@"Hook_EnvVars" : prefs[@"Hook_EnvVars"],
			@"Hook_FilesystemExtra" : prefs[@"Hook_FilesystemExtra"],
			@"Hook_Foundation" : prefs[@"Hook_Foundation"],
			@"Hook_DeviceCheck" : prefs[@"Hook_DeviceCheck"],
			@"Hook_MachBootstrap" : prefs[@"Hook_MachBootstrap"],
			@"Hook_SymLookup" : prefs[@"Hook_SymLookup"],
			@"Hook_LowLevelC" : prefs[@"Hook_LowLevelC"],
			@"Hook_AntiDebugging" : prefs[@"Hook_AntiDebugging"],
			@"Hook_DynamicLibrariesExtra" : prefs[@"Hook_DynamicLibrariesExtra"],
			@"Hook_ObjCRuntime" : prefs[@"Hook_ObjCRuntime"],
			@"Hook_FakeMac" : prefs[@"Hook_FakeMac"],
			@"Tweak_CompatEx" : prefs[@"Tweak_CompatEx"],
			@"Hook_Syscall" : prefs[@"Hook_Syscall"],
			@"Hook_Sandbox" : prefs[@"Hook_Sandbox"]
		};
	}

	if(!enabled) {
		return;
	}

	HBLogDebug(@"%@", @"tweak loaded in app");

	// Initialize Shadow class.
	_srv = [ShadowService new];
	_shadow = [Shadow shadowWithService:_srv];

	if(prefs_load[@"Tweak_CompatEx"]) {
		[_shadow setTweakCompatExtra:[prefs_load[@"Tweak_CompatEx"] boolValue]];
	}

	// Initialize hooks.
	HBLogDebug(@"%@", @"starting hooks");

	if(prefs_load[@"Hook_Filesystem"] && [prefs_load[@"Hook_Filesystem"] boolValue]) {
		HBLogDebug(@"%@", @"+ filesystem");

		shadowhook_libc();
		shadowhook_NSFileManager();
	}

	if(prefs_load[@"Hook_DynamicLibrariesExtra"] && [prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue]) {
		HBLogDebug(@"%@", @"+ dylibex");

		// Register before hooking
		_dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
		_dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);
		_dyld_register_func_for_add_image(shadowhook_dyld_shdw_add_image);
		_dyld_register_func_for_remove_image(shadowhook_dyld_shdw_remove_image);

		shadowhook_dyld_extra();
	}

	if(prefs_load[@"Hook_DynamicLibraries"] && [prefs_load[@"Hook_DynamicLibraries"] boolValue]) {
		HBLogDebug(@"%@", @"+ dylib");

		shadowhook_dyld();
	}

	if(prefs_load[@"Hook_URLScheme"] && [prefs_load[@"Hook_URLScheme"] boolValue]) {
		HBLogDebug(@"%@", @"+ urlscheme");

		shadowhook_UIApplication();
	}

	if(prefs_load[@"Hook_EnvVars"] && [prefs_load[@"Hook_EnvVars"] boolValue]) {
		HBLogDebug(@"%@", @"+ envvars");

		shadowhook_libc_envvar();
		shadowhook_NSProcessInfo();
	}

	if(prefs_load[@"Hook_FilesystemExtra"] && [prefs_load[@"Hook_FilesystemExtra"] boolValue]) {
		HBLogDebug(@"%@", @"+ filesystemex");

		shadowhook_NSFileHandle();
		shadowhook_NSFileVersion();
		shadowhook_NSFileWrapper();
	}

	if(prefs_load[@"Hook_Foundation"] && [prefs_load[@"Hook_Foundation"] boolValue]) {
		HBLogDebug(@"%@", @"+ foundation");

		shadowhook_NSArray();
		shadowhook_NSDictionary();
		shadowhook_NSBundle();
		shadowhook_NSString();
		shadowhook_NSURL();
		shadowhook_NSData();
		shadowhook_UIImage();
	}

	if(prefs_load[@"Hook_DeviceCheck"] && [prefs_load[@"Hook_DeviceCheck"] boolValue]) {
		HBLogDebug(@"%@", @"+ devicecheck");

		shadowhook_DeviceCheck();
	}

	if(prefs_load[@"Hook_MachBootstrap"] && [prefs_load[@"Hook_MachBootstrap"] boolValue]) {
		HBLogDebug(@"%@", @"+ mach");

		shadowhook_mach();
	}

	if(prefs_load[@"Hook_SymLookup"] && [prefs_load[@"Hook_SymLookup"] boolValue]) {
		HBLogDebug(@"%@", @"+ dlsym");

		shadowhook_dyld_symlookup();
	}

	if(prefs_load[@"Hook_LowLevelC"] && [prefs_load[@"Hook_LowLevelC"] boolValue]) {
		HBLogDebug(@"%@", @"+ llc");

		shadowhook_libc_lowlevel();
	}

	if(prefs_load[@"Hook_AntiDebugging"] && [prefs_load[@"Hook_AntiDebugging"] boolValue]) {
		HBLogDebug(@"%@", @"+ debug");

		shadowhook_libc_antidebugging();
	}

	if(prefs_load[@"Hook_ObjCRuntime"] && [prefs_load[@"Hook_ObjCRuntime"] boolValue]) {
		HBLogDebug(@"%@", @"+ objc");

		shadowhook_objc();
	}

	if(prefs_load[@"Hook_FakeMac"] && [prefs_load[@"Hook_FakeMac"] boolValue]) {
		HBLogDebug(@"%@", @"+ m1");

		shadowhook_NSProcessInfo_fakemac();
	}

	if(prefs_load[@"Hook_Syscall"] && [prefs_load[@"Hook_Syscall"] boolValue]) {
		HBLogDebug(@"%@", @"+ syscall");

		shadowhook_syscall();
	}

	if(prefs_load[@"Hook_Sandbox"] && [prefs_load[@"Hook_Sandbox"] boolValue]) {
		HBLogDebug(@"%@", @"+ sandbox");

		shadowhook_sandbox();
	}

	HBLogDebug(@"%@", @"completed hooks");
}
