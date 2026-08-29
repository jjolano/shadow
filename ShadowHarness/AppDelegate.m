#import "AppDelegate.h"
#import "StatusViewController.h"
#import "Detectors.h"
@implementation AppDelegate
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    dispatch_async(dispatch_get_main_queue(), ^{
        SHDWRunAllDetectors();
        [StatusViewController writeStealthReport];
    });
    return YES;
}
@end
