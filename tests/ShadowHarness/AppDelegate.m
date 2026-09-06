#import "AppDelegate.h"
#import "Detectors.h"
#import "StatusViewController.h"
#import <stdlib.h>

@implementation AppDelegate
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    dispatch_async(dispatch_get_main_queue(), ^{
        [StatusViewController writeStealthReport];
    });

    BOOL headless = [NSProcessInfo.processInfo.arguments containsObject:@"--shadow-headless-run-all"];
    // Foreground trigger: a real SpringBoard launch (sbdidlaunch) cannot pass
    // argv, so a marker file lets it drive Run All with a genuine parent —
    // used to A/B freerasp.debug (headless nohup env vs. SpringBoard launch).
    NSString *marker = @"/var/mobile/Documents/ShadowDetectorTests/.run-all-trigger";
    BOOL foregroundTrigger = !headless
        && [NSFileManager.defaultManager fileExistsAtPath:marker];
    if(headless || foregroundTrigger) {
        // Run All needs UIApplicationMain so openURL can reach SpringBoard.
        dispatch_async(dispatch_get_main_queue(), ^{
            if(foregroundTrigger) [NSFileManager.defaultManager removeItemAtPath:marker error:NULL];
            SHDWRunAllDetectorsWithCompletion(^{ if(headless) exit(0); });
        });
        if(headless) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * 60 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ exit(3); });
        }
    }
    return YES;
}
@end
