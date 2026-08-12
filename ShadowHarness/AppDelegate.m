#import "AppDelegate.h"
#import "StatusViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
	// Window/nav stack is built by SceneDelegate via the scene manifest in
	// Info.plist.

	// Automation hook: write full diagnostics to a file at launch, before
	// any scene exists. viewWillAppear-based capture fails when the device
	// is locked (scene never activates), so this is the deterministic path.
	// Try the container Documents dir first, then /var/mobile/Documents
	// (unsandboxed installs resolve NSDocumentDirectory differently).
	StatusViewController* statusViewController = [StatusViewController new];
	NSString* dump = [statusViewController diagnosticsString];

	NSString* containerPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
	if(containerPath) {
		[dump writeToFile:[containerPath stringByAppendingPathComponent:@"ShadowDiagnostics.txt"]
			atomically:YES encoding:NSUTF8StringEncoding error:nil];
	}
	[dump writeToFile:@"/var/mobile/Documents/ShadowDiagnostics.txt"
		atomically:YES encoding:NSUTF8StringEncoding error:nil];

	return YES;
}

@end
