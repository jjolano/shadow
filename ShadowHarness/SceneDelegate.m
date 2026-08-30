#import "SceneDelegate.h"
#import "DetectorDashboard.h"
#import "StatusViewController.h"
@implementation SceneDelegate
- (void)scene:(UIScene*)scene willConnectToSession:(UISceneSession*)session options:(UISceneConnectionOptions*)connectionOptions {
    if(![scene isKindOfClass:[UIWindowScene class]]) return;
    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene*)scene];
    SHDWSDKListController* dashboard = [[SHDWSDKListController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController* navigationController = [[UINavigationController alloc] initWithRootViewController:dashboard];
    navigationController.navigationBar.prefersLargeTitles = YES;
    self.window.rootViewController = navigationController;
    [self.window makeKeyAndVisible];
    dispatch_async(dispatch_get_main_queue(), ^{
        [StatusViewController writeStealthReport];
    });
}
- (void)sceneDidBecomeActive:(UIScene*)scene {
    dispatch_async(dispatch_get_main_queue(), ^{
        [StatusViewController writeStealthReport];
        [[NSNotificationCenter defaultCenter] postNotificationName:SHDWDetectorResultsChanged object:nil];
    });
}
@end
