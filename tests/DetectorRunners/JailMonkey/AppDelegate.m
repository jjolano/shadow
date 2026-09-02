#import <UIKit/UIKit.h>

#import "../RunnerSupport.h"
#import "../../../.detector-deps/JailMonkey/JailMonkey/JailMonkey.h"

@interface JailMonkey (RunnerChecks)
- (BOOL)checkPaths;
- (BOOL)checkSchemes;
- (BOOL)canViolateSandbox;
- (BOOL)canFork;
- (BOOL)checkSymlinks;
- (BOOL)checkDylibs;
- (BOOL)isDebugged;
- (NSString *)checkPathsMessage;
- (NSString *)checkSchemesMessage;
- (NSString *)checkSymlinksMessage;
- (NSString *)checkDylibsMessage;
@end

@interface JailMonkeyAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic) BOOL started;
@end

static NSDictionary *JailMonkeyCheck(NSString *identifier, NSString *name, BOOL passed, NSString *message) {
    return @{ @"id": identifier, @"name": name, @"passed": @(passed), @"message": message ?: @"" };
}

@implementation JailMonkeyAppDelegate

- (void)runURL:(NSURL *)url {
    NSDictionary *parameters = SHDWRunnerParameters(url);
    NSString *callback = parameters[@"callback"];
    if (self.started || !callback.length) return;
    self.started = YES;

    JailMonkey *detector = [JailMonkey new];
    BOOL paths = [detector checkPaths];
    BOOL schemes = [detector checkSchemes];
    BOOL sandbox = [detector canViolateSandbox];
    BOOL forked = [detector canFork];
    BOOL symlinks = [detector checkSymlinks];
    BOOL dylibs = [detector checkDylibs];
    BOOL debugged = [detector isDebugged];
    NSArray *checks = @[
        JailMonkeyCheck(@"jailmonkey.paths", @"Suspicious paths", !paths, [detector checkPathsMessage]),
        JailMonkeyCheck(@"jailmonkey.schemes", @"Suspicious URL schemes", !schemes, [detector checkSchemesMessage]),
        JailMonkeyCheck(@"jailmonkey.sandbox", @"Sandbox violation", !sandbox, sandbox ? @"write succeeded" : @"write denied"),
        JailMonkeyCheck(@"jailmonkey.fork", @"Fork", !forked, forked ? @"fork succeeded" : @"fork denied"),
        JailMonkeyCheck(@"jailmonkey.symlinks", @"Suspicious symlinks", !symlinks, [detector checkSymlinksMessage]),
        JailMonkeyCheck(@"jailmonkey.dylibs", @"Suspicious dylibs", !dylibs, [detector checkDylibsMessage]),
        JailMonkeyCheck(@"jailmonkey.debugger", @"Debugger", !debugged, debugged ? @"debugger attached" : @"not debugged"),
    ];
    BOOL clean = YES;
    for (NSDictionary *check in checks) clean = clean && [check[@"passed"] boolValue];
    SHDWRunnerFinish(@"jailmonkey", @"JailMonkey", @"v2.8.5", clean ? @"clean" : @"jailbroken",
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
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(JailMonkeyAppDelegate.class));
    }
}
