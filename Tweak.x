#import <HBLog.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <Foundation/Foundation.h>
#import <AppSupport/CPDistributedMessagingCenter.h>
#import <Cephei/HBPreferences.h>

#import "api/Shadow.h"
#import "api/ShadowXPC.h"
#import "hooks/hooks.h"

Shadow* _shadow = nil;
ShadowXPC* _xpc = nil;

%group hook_springboard
%hook SpringBoard
- (void)applicationDidFinishLaunching:(UIApplication *)application {
    %orig;
	
	// todo: Maybe preload some items into cache? Probably do in the background on a separate thread.
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
		@"Hook_FilesystemExtra" : @(YES),
		@"Hook_CollectionClasses" : @(YES),
		@"Hook_BundleClass" : @(YES),
		@"Hook_StringClass" : @(YES),
		@"Hook_URLClass" : @(YES),
		@"Hook_DataClass" : @(YES),
		@"Hook_ImageClass" : @(YES),
		@"Hook_DeviceCheck" : @(NO),
		@"Hook_MachBootstrap" : @(NO),
		@"Hook_SymLookup" : @(NO),
		@"Hook_LowLevelC" : @(NO),
		@"Hook_AntiDebugging" : @(NO),
		@"Hook_DynamicLibrariesExtra" : @(NO)
	}];

	// Determine the application we're injected into.
	NSString* bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];

	// Injected into SpringBoard.
	if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
		// Create Shadow instance (with XPC methods).
		_xpc = [ShadowXPC new];

		if(!_xpc) {
			return;
		}

		// Start RocketBootstrap server.
		CPDistributedMessagingCenter* messagingCenter = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
		rocketbootstrap_distributedmessagingcenter_apply(messagingCenter);
		[messagingCenter runServerOnCurrentThread];

		// Register messages.
		[messagingCenter registerForMessageName:@"ping" target:_xpc selector:@selector(handleMessageNamed:withUserInfo:)];
		[messagingCenter registerForMessageName:@"isPathRestricted" target:_xpc selector:@selector(handleMessageNamed:withUserInfo:)];
		[messagingCenter registerForMessageName:@"getURLSchemes" target:_xpc selector:@selector(handleMessageNamed:withUserInfo:)];

		// Unlock shadowd service.
		rocketbootstrap_unlock("me.jjolano.shadow");

		HBLogDebug(@"%@", @"xpc service started: me.jjolano.shadow");

		%init(hook_springboard);
		return;
	}

	// Only load Shadow for App Store applications.
	// Don't load for App Extensions (.. unless developers are adding detection in those too :/)
	NSString* bundlePath = [[NSBundle mainBundle] bundlePath];
	if(![[NSBundle mainBundle] appStoreReceiptURL] || [bundlePath hasPrefix:@"/Applications"] || [bundlePath hasSuffix:@".appex"]) {
		return;
	}

	NSDictionary* prefs_load = @{
		@"App_Enabled" : prefs[@"Global_Enabled"],
		@"Hook_Filesystem" : prefs[@"Hook_Filesystem"],
		@"Hook_DynamicLibraries" : prefs[@"Hook_DynamicLibraries"],
		@"Hook_URLScheme" : prefs[@"Hook_URLScheme"],
		@"Hook_EnvVars" : prefs[@"Hook_EnvVars"],
		@"Hook_FilesystemExtra" : prefs[@"Hook_FilesystemExtra"],
		@"Hook_CollectionClasses" : prefs[@"Hook_CollectionClasses"],
		@"Hook_BundleClass" : prefs[@"Hook_BundleClass"],
		@"Hook_StringClass" : prefs[@"Hook_StringClass"],
		@"Hook_URLClass" : prefs[@"Hook_URLClass"],
		@"Hook_DataClass" : prefs[@"Hook_DataClass"],
		@"Hook_ImageClass" : prefs[@"Hook_ImageClass"],
		@"Hook_DeviceCheck" : prefs[@"Hook_DeviceCheck"],
		@"Hook_MachBootstrap" : prefs[@"Hook_MachBootstrap"],
		@"Hook_SymLookup" : prefs[@"Hook_SymLookup"],
		@"Hook_LowLevelC" : prefs[@"Hook_LowLevelC"],
		@"Hook_AntiDebugging" : prefs[@"Hook_AntiDebugging"],
		@"Hook_DynamicLibrariesExtra" : prefs[@"Hook_DynamicLibrariesExtra"]
	};

	// Determine whether to load the rest of the tweak.
	// Load app-specific settings, if enabled.
	NSDictionary* prefs_app = prefs[bundleIdentifier];
	if(prefs_app && [prefs_app[@"App_Override"] boolValue]) {
		prefs_load = prefs_app;
	}

	if(prefs_load[@"App_Enabled"] && ![prefs_load[@"App_Enabled"] boolValue]) {
		return;
	}

	HBLogDebug(@"%@", @"tweak loaded in app");

	// Initialize Shadow class.
	_shadow = [Shadow new];

	if(!_shadow) {
		HBLogDebug(@"%@", @"failed to load class");
		return;
	}

	// Initialize connection to shadowd.
	CPDistributedMessagingCenter* c = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
	rocketbootstrap_distributedmessagingcenter_apply(c);

	[_shadow setMessagingCenter:c];

	// Test communication to shadowd.
	NSDictionary* response;
	response = [c sendMessageAndReceiveReplyName:@"ping" userInfo:nil];

	if(response) {
		HBLogDebug(@"%@: %@", @"bypass version", [response objectForKey:@"bypass_version"]);
		HBLogDebug(@"%@: %@", @"api version", [response objectForKey:@"api_version"]);
	} else {
		HBLogDebug(@"%@", @"failed to communicate with xpc");
		return;
	}

	// Preload data from shadowd.
	response = [c sendMessageAndReceiveReplyName:@"getURLSchemes" userInfo:nil];

	if(response) {
		NSArray<NSString *>* schemes = [response objectForKey:@"schemes"];
		[_shadow setURLSchemes:schemes];
	}

	// Initialize hooks.
	if(prefs_load[@"Hook_Filesystem"] && [prefs_load[@"Hook_Filesystem"] boolValue]) {
		shadowhook_libc();
		shadowhook_NSFileManager();
	}

	if(prefs_load[@"Hook_DynamicLibrariesExtra"] && [prefs_load[@"Hook_DynamicLibrariesExtra"] boolValue]) {
		// Register before hooking
		_dyld_register_func_for_add_image(shadowhook_dyld_updatelibs);
		_dyld_register_func_for_remove_image(shadowhook_dyld_updatelibs_r);
		_dyld_register_func_for_add_image(shadowhook_dyld_shdw_add_image);
		_dyld_register_func_for_remove_image(shadowhook_dyld_shdw_remove_image);
		
		shadowhook_dyld_extra();
	}

	if(prefs_load[@"Hook_DynamicLibraries"] && [prefs_load[@"Hook_DynamicLibraries"] boolValue]) {
		shadowhook_dyld();
	}

	if(prefs_load[@"Hook_URLScheme"] && [prefs_load[@"Hook_URLScheme"] boolValue]) {
		shadowhook_UIApplication();
	}

	if(prefs_load[@"Hook_EnvVars"] && [prefs_load[@"Hook_EnvVars"] boolValue]) {
		shadowhook_libc_envvar();
		shadowhook_NSProcessInfo();
	}

	if(prefs_load[@"Hook_FilesystemExtra"] && [prefs_load[@"Hook_FilesystemExtra"] boolValue]) {
		shadowhook_NSFileHandle();
		shadowhook_NSFileVersion();
		shadowhook_NSFileWrapper();
	}

	if(prefs_load[@"Hook_CollectionClasses"] && [prefs_load[@"Hook_CollectionClasses"] boolValue]) {
		shadowhook_NSArray();
		shadowhook_NSDictionary();
	}

	if(prefs_load[@"Hook_BundleClass"] && [prefs_load[@"Hook_BundleClass"] boolValue]) {
		shadowhook_NSBundle();
	}

	if(prefs_load[@"Hook_StringClass"] && [prefs_load[@"Hook_StringClass"] boolValue]) {
		shadowhook_NSString();
	}

	if(prefs_load[@"Hook_URLClass"] && [prefs_load[@"Hook_URLClass"] boolValue]) {
		shadowhook_NSURL();
	}

	if(prefs_load[@"Hook_DataClass"] && [prefs_load[@"Hook_DataClass"] boolValue]) {
		shadowhook_NSData();
	}

	if(prefs_load[@"Hook_ImageClass"] && [prefs_load[@"Hook_ImageClass"] boolValue]) {
		shadowhook_UIImage();
	}

	if(prefs_load[@"Hook_DeviceCheck"] && [prefs_load[@"Hook_DeviceCheck"] boolValue]) {
		shadowhook_DeviceCheck();
	}

	if(prefs_load[@"Hook_MachBootstrap"] && [prefs_load[@"Hook_MachBootstrap"] boolValue]) {
		shadowhook_mach();
	}

	if(prefs_load[@"Hook_SymLookup"] && [prefs_load[@"Hook_SymLookup"] boolValue]) {
		shadowhook_dyld_symlookup();
	}

	if(prefs_load[@"Hook_LowLevelC"] && [prefs_load[@"Hook_LowLevelC"] boolValue]) {
		shadowhook_libc_lowlevel();
	}

	if(prefs_load[@"Hook_AntiDebugging"] && [prefs_load[@"Hook_AntiDebugging"] boolValue]) {
		shadowhook_libc_antidebugging();
	}

	HBLogDebug(@"%@", @"hooks initialized");
}
