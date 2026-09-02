#import <DTTJailbreakDetection.h>
#import <UIKit/UIKit.h>

#import "../RunnerSupport.h"

@interface DTTAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic) BOOL started;
@end

static NSDictionary *DTTCheck(NSString *identifier, NSString *name, BOOL passed, NSString *message) {
    return @{ @"id": identifier, @"name": name, @"passed": @(passed), @"message": message ?: @"" };
}

@implementation DTTAppDelegate

- (void)runURL:(NSURL *)url {
    NSDictionary *parameters = SHDWRunnerParameters(url);
    NSString *callback = parameters[@"callback"];
    if (self.started || !callback.length) return;
    self.started = YES;

    BOOL jailbroken = [DTTJailbreakDetection isJailbroken];
    NSArray *checks = @[DTTCheck(@"dtt.isJailbroken", @"isJailbroken", !jailbroken,
        jailbroken ? @"Library returned YES" : @"Library returned NO")];
    SHDWRunnerFinish(@"dttjailbreakdetection", @"DTTJailbreakDetection", @"0.2.0+cedd424",
        jailbroken ? @"jailbroken" : @"clean",
        @[@{ @"phase": @"startup", @"clean": @((BOOL)!jailbroken), @"checks": checks }], nil, callback);
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
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(DTTAppDelegate.class));
    }
}
