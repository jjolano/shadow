#import "Shadow.h"

#include <sys/snapshot.h>
#include <sqlite3.h>

#import <rocketbootstrap/rocketbootstrap.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

static void create_origfs_map(void) {

}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		// Create Shadow instance.
		Shadow* shadow = [Shadow sharedInstance];

		if(!shadow) {
			return 1;
		}

		// Check new install file.
		if([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/Shadow/.new_install"]) {
			// (re) Create the orig-fs map.
			create_origfs_map();

			// Delete new install file.
			[[NSFileManager defaultManager] removeItemAtPath:@"/Library/Shadow/.new_install" error:nil];
		}

		// Start RocketBootstrap server.
		CPDistributedMessagingCenter* messagingCenter = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
		rocketbootstrap_distributedmessagingcenter_apply(messagingCenter);
		[messagingCenter runServerOnCurrentThread];

		// Register messages.
		[messagingCenter registerForMessageName:@"isRestrictedPath" target:shadow selector:@selector(handleMessageNamed:withUserInfo:)];

		// Keep daemon running.
		[[NSRunLoop currentRunLoop] run];

		return 0;
	}
}
