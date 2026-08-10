#import "AppDelegate.h"

#import "StatusViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
	self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];

	StatusViewController* statusViewController = [StatusViewController new];
	UINavigationController* navigationController = [[UINavigationController alloc] initWithRootViewController:statusViewController];
	self.window.rootViewController = navigationController;

	[self.window makeKeyAndVisible];

	return YES;
}

@end
