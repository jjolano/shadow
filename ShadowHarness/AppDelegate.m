#import "AppDelegate.h"
#import "StatusViewController.h"
@implementation AppDelegate
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    dispatch_async(dispatch_get_main_queue(), ^{
        [StatusViewController writeStealthReport];
    });
    return YES;
}
@end
