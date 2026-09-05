#import <UIKit/UIKit.h>

#import "../RunnerSupport.h"
#import "JB.h"

@interface isJailbrokenAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic) BOOL started;
@end

static NSDictionary *ISJBCheck(NSString *identifier, NSString *name, BOOL passed, NSString *message) {
    return @{ @"id": identifier, @"name": name, @"passed": @(passed), @"message": message ?: @"" };
}

@implementation isJailbrokenAppDelegate

- (void)runURL:(NSURL *)url {
    NSDictionary *parameters = SHDWRunnerParameters(url);
    NSString *callback = parameters[@"callback"];
    if (self.started || !callback.length) return;
    self.started = YES;

    // isJb() aggregates cydia-URL, 44 suspicious paths, symlink lstat, fork(),
    // and /private write into one verdict; the granular signals below are the
    // SDK's other public probes. A "passed" check means "no jailbreak signal".
    BOOL jailbroken = isJb();
    BOOL injected = isInjectedWithDynamicLibrary();
    BOOL debugged = isDebugged();
    BOOL onMac = isRunningOnMac();

    NSArray *checks = @[
        ISJBCheck(@"isjailbroken.jailbreak", @"Jailbreak (paths/symlink/fork/write/URL)", !jailbroken,
            jailbroken ? @"jailbreak signal detected" : @"no jailbreak signal"),
        ISJBCheck(@"isjailbroken.dylib", @"Injected dynamic library", !injected,
            injected ? @"suspicious dylib in image list" : @"no suspicious dylib"),
        ISJBCheck(@"isjailbroken.debugger", @"Debugger (P_TRACED)", !debugged,
            debugged ? @"debugger attached" : @"not debugged"),
        ISJBCheck(@"isjailbroken.ios_on_mac", @"Running as iOS-on-Mac", !onMac,
            onMac ? @"process is iOS app on Mac" : @"native iOS device"),
    ];
    BOOL clean = YES;
    for (NSDictionary *check in checks) clean = clean && [check[@"passed"] boolValue];
    SHDWRunnerFinish(@"isjailbroken", @"isJailbroken", @"main@60a5f55", clean ? @"clean" : @"jailbroken",
        @[@{ @"phase": @"startup", @"clean": @(clean), @"checks": checks }], nil, callback);
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [UIViewController new];
    self.window.rootViewController.view.backgroundColor = UIColor.systemBackgroundColor;
    [self.window makeKeyAndVisible];
    [self runURL:options[UIApplicationLaunchOptionsURLKey]];
    return YES;
}

- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url options:(NSDictionary *)options {
    [self runURL:url];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(isJailbrokenAppDelegate.class));
    }
}
