#import "AppDelegate.h"
#import "StatusViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
	// Window/nav stack is built by SceneDelegate via the scene manifest in
	// Info.plist.

	// Refresh the pre-main report once UIApplication is initialized. The
	// producer does not depend on this lifecycle callback being delivered.
	[StatusViewController writeStealthReport];

	return YES;
}

@end
