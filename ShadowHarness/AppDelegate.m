#import "AppDelegate.h"
#import "StatusViewController.h"
#import "Detectors.h"
@implementation AppDelegate
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    SHDWRunAllDetectors();
    [StatusViewController writeStealthReport];
    return YES;
}
@end
