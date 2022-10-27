#import "ShadowXPC.h"

#import <HBLog.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

int main(int argc, char *argv[], char *envp[]) {
	// Create Shadow instance (with XPC methods).
	ShadowXPC* _shadow = [ShadowXPC new];

	if(!_shadow) {
		return 1;
	}

	// Start RocketBootstrap server.
	CPDistributedMessagingCenter* messagingCenter = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadowd"];
	rocketbootstrap_distributedmessagingcenter_apply(messagingCenter);
	[messagingCenter runServerOnCurrentThread];

	// Register messages.
	[messagingCenter registerForMessageName:@"isPathRestricted" target:_shadow selector:@selector(handleMessageNamed:withUserInfo:)];

	HBLogInfo(@"%@", @"xpc service started: me.jjolano.shadowd");

	// Keep daemon running.
	[[NSRunLoop currentRunLoop] run];

	return 0;
}
