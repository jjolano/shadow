#import <HBLog.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <Foundation/Foundation.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#import "api/Shadow.h"
#import "api/ShadowXPC.h"
#import "hooks/hooks.h"

Shadow* _shadow = nil;

%ctor {
	// Determine the application we're injected into.
	NSString* bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];

	// Injected into SpringBoard.
	if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
		// Create Shadow instance (with XPC methods).
		ShadowXPC* _xpc = [ShadowXPC new];

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

		HBLogDebug(@"%@", @"[shadow] xpc service started: me.jjolano.shadow");
		return;
	}

	// Only load Shadow for App Store applications.
	if(![[NSBundle mainBundle] appStoreReceiptURL] || [[[NSBundle mainBundle] bundlePath] hasPrefix:@"/Applications"]) {
		return;
	}

	HBLogDebug(@"%@", @"[shadow] tweak loaded");

	// Initialize Shadow class.
	_shadow = [Shadow new];

	if(!_shadow) {
		HBLogDebug(@"%@", @"[shadow] failed to load class");
		return;
	}

	// Initialize connection to shadowd.
	CPDistributedMessagingCenter* c = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
	rocketbootstrap_distributedmessagingcenter_apply(c);

	[_shadow setMessagingCenter:c];

	// Preload data from shadowd.
	NSDictionary* response = [c sendMessageAndReceiveReplyName:@"getURLSchemes" userInfo:nil];

	if(response) {
		NSArray<NSString *>* schemes = [response objectForKey:@"schemes"];
		[_shadow setURLSchemes:schemes];
	}

	// Initialize hooks.
	shadowhook_DeviceCheck();
	shadowhook_dyld();
	shadowhook_libc();
	shadowhook_mach();
	shadowhook_NSArray();
	shadowhook_NSBundle();
	shadowhook_NSData();
	shadowhook_NSDictionary();
	shadowhook_NSFileHandle();
	shadowhook_NSFileManager();
	shadowhook_NSFileVersion();
	shadowhook_NSFileWrapper();
	shadowhook_NSProcessInfo();
	shadowhook_NSString();
	shadowhook_NSURL();
	shadowhook_UIApplication();
	shadowhook_UIImage();

	HBLogDebug(@"%@", @"[shadow] hooks initialized");
}
