#import "AppDelegate.h"
#import "Detectors.h"
#import "StatusViewController.h"
#import <stdlib.h>

@implementation AppDelegate
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    dispatch_async(dispatch_get_main_queue(), ^{
        [StatusViewController writeStealthReport];
    });

    if([NSProcessInfo.processInfo.arguments containsObject:@"--shadow-headless-run-all"]) {
        // Run All needs UIApplicationMain so openURL can reach SpringBoard.
        dispatch_async(dispatch_get_main_queue(), ^{
            SHDWRunAllDetectorsWithCompletion(^{ exit(0); });
        });
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * 60 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(3); });
    }
    return YES;
}
@end
