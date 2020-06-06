#include <sys/snapshot.h>

#import <Foundation/Foundation.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#import "Shadow.h"

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		// Create Shadow instance.
		Shadow* shadow = [Shadow sharedInstance];

		if(!shadow) {
			NSLog(@"error: failed to initialize Shadow instance.");
			return 1;
		}

		// Start RocketBootstrap server.
		CPDistributedMessagingCenter* messagingCenter = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
		rocketbootstrap_distributedmessagingcenter_apply(messagingCenter);
		[messagingCenter runServerOnCurrentThread];

		// Register messages.
		[messagingCenter registerForMessageName:@"isRestrictedPath" target:shadow selector:@selector(handleMessageNamed:withUserInfo:)];

		NSLog(@"shadowd ready.");

		// Keep daemon running.
		[[NSRunLoop currentRunLoop] run];

		return 0;
	}
}
