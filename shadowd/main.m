#include <sys/snapshot.h>
#include <sqlite3.h>

#import <Foundation/Foundation.h>
#import <rocketbootstrap/rocketbootstrap.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#import "Shadow.h"

static void create_origfs_map(void) {

}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		// Create Shadow instance.
		Shadow* shadow = [Shadow sharedInstance];

		if(!shadow) {
			HBLogError(@"[shadow] error: failed to initialize Shadow instance.");
			return 1;
		}

		// Check new install file.
		if([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/Shadow/.new_install"]) {
			HBLogInfo(@"[shadow] new install detected.");

			// (re) Create the orig-fs map.
			HBLogInfo(@"[shadow] generating orig-fs map...");
			create_origfs_map();

			// Delete new install file.
			[[NSFileManager defaultManager] removeItemAtPath:@"/Library/Shadow/.new_install" error:nil];
		}

		// Start RocketBootstrap server.
		HBLogInfo(@"[shadow] starting messaging center for rocketbootstrap...");

		CPDistributedMessagingCenter* messagingCenter = [CPDistributedMessagingCenter centerNamed:@"me.jjolano.shadow"];
		rocketbootstrap_distributedmessagingcenter_apply(messagingCenter);
		[messagingCenter runServerOnCurrentThread];

		// Register messages.
		HBLogInfo(@"[shadow] registering messages...");
		[messagingCenter registerForMessageName:@"isRestrictedPath" target:shadow selector:@selector(handleMessageNamed:withUserInfo:)];

		HBLogInfo(@"[shadow] shadowd ready.");

		// Keep daemon running.
		[[NSRunLoop currentRunLoop] run];

		return 0;
	}
}
