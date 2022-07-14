#import <HBLog.h>
#import <Cephei/HBPreferences.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#import "hooks/hooks.h"

static CPDistributedMessagingCenter* c = nil;
NSString* bundleIdentifier = nil;

BOOL shadowd_isRestricted(NSURL* url) {
	if(!c) {
		return NO;
	}

	// Query shadowd with path.
	NSDictionary* result = [c sendMessageAndReceiveReplyName:@"shadowd_isRestricted" userInfo:@{
		@"bundleIdentifier" : bundleIdentifier,
		@"url" : url
	}];

	if(result && [result[@"restricted"] boolValue]) {
		return YES;
	}

	return NO;
}

%ctor {
	// Determine the application we're injected into.
	bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];

	// Injected into SpringBoard.
	if([bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
		// Load tweak preferences.
		HBPreferences* shadowPrefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];

		[shadowPrefs registerDefaults:@{
			@"tweak": @{
				@"prefs_revision": @(1)
			}
		}];

		// Initialize tweak preferences.
		NSDictionary* tweakPrefs = [shadowPrefs objectForKey:@"tweak"];
		NSMutableDictionary* tweakPrefsNew = [tweakPrefs mutableCopy];

		/*
		if([tweakPrefs[@"prefs_revision"] intValue] < 2) {
			// Code for upgrading preferences from rev 1...

			tweakPrefsNew[@"prefs_revision"] = @(2);
		}
		*/

		// Update prefs if necessary.
		if([tweakPrefsNew[@"prefs_revision"] intValue] != [tweakPrefs[@"prefs_revision"] intValue]) {
			// tweakPrefs = [NSDictionary dictionaryWithDictionary:tweakPrefsNew];
			[shadowPrefs setObject:tweakPrefsNew forKey:@"tweak"];
		}

		// Unlock shadowd service for IPC.
		rocketbootstrap_unlock("me.jjolano.shadow");

		return;
	}

	// Load tweak preferences.
	HBPreferences* shadowPrefs = [HBPreferences preferencesForIdentifier:@"me.jjolano.shadow"];

	// Check if Shadow is enabled in this application.
	NSDictionary* appPrefs = [shadowPrefs objectForKey:@"app"];
	NSDictionary* bundlePrefs = appPrefs[bundleIdentifier];

	if(!bundlePrefs || !bundlePrefs[@"enabled"]) {
		return;
	}

	// Initialize connection to shadowd.
	c = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
	rocketbootstrap_distributedmessagingcenter_apply(c);

	// Activate base hooks.
	
	
	// Activate extra features (if enabled).
	
}
