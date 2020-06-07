#import <Cephei/HBPreferences.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#import "hooks/hooks.h"

static CPDistributedMessagingCenter* c = nil;
NSString* bundleIdentifier = nil;

BOOL isPathRestricted(NSString* path) {
	if(!c) {
		return NO;
	}

	// Query shadowd with path.
	NSDictionary* result = [c sendMessageAndReceiveReplyName:@"isPathRestricted" userInfo:@{
		@"bundleIdentifier" : bundleIdentifier,
		@"path" : path
	}];

	if(!result || ![result[@"restricted"] boolValue]) {
		return NO;
	}

	return YES;
}

%ctor {
	// Determine the application we're injected into.
	bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];

	// Injected into SpringBoard.
	if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
		// Unlock shadowd service for IPC.
		rocketbootstrap_unlock("me.jjolano.shadow");
		return;
	}

	// Load tweak preferences.
	HBPreferences* shadowPrefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];

	// Check if Shadow is enabled in this application.
	NSDictionary* bundlePrefs = [shadowPrefs objectForKey:bundleIdentifier];

	if(!bundlePrefs || !bundlePrefs[@"enabled"]) {
		return;
	}

	// Initialize connection to shadowd.
	c = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
	rocketbootstrap_distributedmessagingcenter_apply(c);

	// Activate base hooks.
	
	
	// Activate extra features (if enabled).
	
}
