#import "SceneDelegate.h"

#import "DetectorDashboard.h"
#import "StatusViewController.h"

@implementation SceneDelegate

- (void)scene:(UIScene*)scene willConnectToSession:(UISceneSession*)session options:(UISceneConnectionOptions*)connectionOptions {
	if(![scene isKindOfClass:[UIWindowScene class]]) {
		return;
	}

	self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene*)scene];

	SHDWSDKListController* dashboard = [[SHDWSDKListController alloc] initWithStyle:UITableViewStyleInsetGrouped];
	UINavigationController* navigationController = [[UINavigationController alloc] initWithRootViewController:dashboard];
	navigationController.navigationBar.prefersLargeTitles = YES;
	self.window.rootViewController = navigationController;

	[self.window makeKeyAndVisible];
}

- (void)sceneDidBecomeActive:(UIScene*)scene {
	// A warm uiopen reuses the existing process, so main/viewDidLoad do not
	// run again. Consume the driver's new nonce when this scene is reactivated.
	[StatusViewController writeStealthReport];
	[[NSNotificationCenter defaultCenter] postNotificationName:SHDWDetectorResultsChanged object:nil];
}

@end
