#import <HBLog.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <Foundation/Foundation.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#import "api/Shadow.h"
#import "hooks/hooks.h"

%ctor {
	// Determine the application we're injected into.
	NSString* bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];

	// Injected into SpringBoard.
	if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
		// Unlock shadowd service.
		rocketbootstrap_unlock("me.jjolano.shadowd");

		HBLogInfo(@"%@", @"[shadow] unlocked xpc service from SpringBoard");
		return;
	}

	// Only load Shadow for App Store applications.
	if(![[NSBundle mainBundle] appStoreReceiptURL]) {
		return;
	}

	HBLogInfo(@"%@", @"[shadow] tweak loaded");

	// Initialize Shadow class.
	Shadow* shadow = [Shadow sharedInstance];

	// Initialize connection to shadowd.
	CPDistributedMessagingCenter* c = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadowd"];
	rocketbootstrap_distributedmessagingcenter_apply(c);

	[shadow setMessagingCenter:c];

	// Initialize hooks.
	shadowhook_libc();
	shadowhook_dyld();
	shadowhook_NSFileManager();

	HBLogInfo(@"%@", @"[shadow] hooks initialized");
}
