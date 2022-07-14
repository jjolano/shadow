#import "Shadow.h"

#import <rocketbootstrap/rocketbootstrap.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		// Create Shadow instance.
		Shadow* shadow = [Shadow sharedInstance];

		if(!shadow) {
			return 1;
		}

		// Start RocketBootstrap server.
		CPDistributedMessagingCenter* messagingCenter = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
		rocketbootstrap_distributedmessagingcenter_apply(messagingCenter);
		[messagingCenter runServerOnCurrentThread];

		// Register messages.
		[messagingCenter registerForMessageName:@"shadowd_isRestricted" target:shadow selector:@selector(handleMessageNamed:withUserInfo:)];

		// Keep daemon running.
		[[NSRunLoop currentRunLoop] run];

		return 0;
	}
}
