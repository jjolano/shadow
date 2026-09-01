#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <bootstrap.h>

#import "../RunnerSupport.h"

void detect_rootlessJB(void);
void detect_kernBypass(void);
void detect_chroot(void);
void detect_mount_fs(void);
void detect_bootstraps(void);
void detect_trollStoredFilza(void);
void detect_jailbreakd(void);
void detect_proc_flags(void);
void detect_jb_payload(void);
void detect_exception_port(void);
void detect_jb_preboot(void);
void detect_jailbroken_apps(void);
void detect_removed_varjb(void);
void detect_fugu15Max(void);
void detect_url_schemes(void);
void detect_jbapp_plugins(void);
void detect_jailbreak_sigs(void);
void detect_jailbreak_port(void);
void detect_launchd_jbserver(void);
void detect_launchd_jb_mach_server(void);
void detect_passcode_status(void);
void detect_cfprefsd_hook(void);
void detect_launchd_ipchook(void);
void detect_bind_mounts(void);
void detect_launchd_deplatformized(void);

@interface RoothiderAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic) BOOL started;
@end

static NSDictionary *RoothiderCheck(NSString *identifier, NSString *name, BOOL passed, NSString *message) {
    return @{ @"id": identifier, @"name": name, @"passed": @(passed), @"message": message ?: @"" };
}

static NSMutableArray<NSString *> *RoothiderFindings;

void shdw_roothider_log(NSString *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    if(message.length) [RoothiderFindings addObject:message];
}

static NSDictionary *RoothiderRun(NSString *identifier, NSString *name, void (*detector)(void)) {
    RoothiderFindings = [NSMutableArray array];
    detector();
    BOOL detected = RoothiderFindings.count > 0;
    NSString *message = detected ? [RoothiderFindings componentsJoinedByString:@"; "] : @"No finding";
    return RoothiderCheck(identifier, name, !detected, message);
}

@implementation RoothiderAppDelegate

- (void)runURL:(NSURL *)url {
    NSDictionary *parameters = SHDWRunnerParameters(url);
    NSString *callback = parameters[@"callback"];
    if (self.started || !callback.length) return;
    self.started = YES;

    NSArray *checks = @[
        RoothiderRun(@"roothider.rootlessJB", @"Rootless jailbreak", detect_rootlessJB),
        RoothiderRun(@"roothider.kernBypass", @"Kernel bypass", detect_kernBypass),
        RoothiderRun(@"roothider.chroot", @"Chroot", detect_chroot),
        RoothiderRun(@"roothider.mount_fs", @"Mounted filesystems", detect_mount_fs),
        RoothiderRun(@"roothider.bootstraps", @"Bootstrap files", detect_bootstraps),
        RoothiderRun(@"roothider.trollStoredFilza", @"TrollStore Filza", detect_trollStoredFilza),
        RoothiderRun(@"roothider.jailbreakd", @"Jailbreak daemon", detect_jailbreakd),
        RoothiderRun(@"roothider.proc_flags", @"Process flags", detect_proc_flags),
        RoothiderRun(@"roothider.jb_payload", @"Jailbreak payload", detect_jb_payload),
        RoothiderRun(@"roothider.exception_port", @"Exception port", detect_exception_port),
        RoothiderRun(@"roothider.jb_preboot", @"Preboot jailbreak", detect_jb_preboot),
        RoothiderRun(@"roothider.jailbroken_apps", @"Jailbreak apps", detect_jailbroken_apps),
        RoothiderRun(@"roothider.removed_varjb", @"Removed /var/jb", detect_removed_varjb),
        RoothiderRun(@"roothider.fugu15Max", @"Fugu15 Max", detect_fugu15Max),
        RoothiderRun(@"roothider.url_schemes", @"URL schemes", detect_url_schemes),
        RoothiderRun(@"roothider.jbapp_plugins", @"Jailbreak app plugins", detect_jbapp_plugins),
        RoothiderRun(@"roothider.jailbreak_sigs", @"Jailbreak signatures", detect_jailbreak_sigs),
        RoothiderRun(@"roothider.jailbreak_port", @"Jailbreak ports", detect_jailbreak_port),
        RoothiderRun(@"roothider.launchd_jbserver", @"Launchd jailbreak server", detect_launchd_jbserver),
        RoothiderRun(@"roothider.launchd_jb_mach_server", @"Launchd Mach server", detect_launchd_jb_mach_server),
        RoothiderRun(@"roothider.passcode_status", @"Passcode status", detect_passcode_status),
        RoothiderRun(@"roothider.cfprefsd_hook", @"cfprefsd hook", detect_cfprefsd_hook),
        RoothiderRun(@"roothider.launchd_ipchook", @"Launchd IPC hook", detect_launchd_ipchook),
        RoothiderRun(@"roothider.bind_mounts", @"Bind mounts", detect_bind_mounts),
        RoothiderRun(@"roothider.launchd_deplatformized", @"Launchd deplatformized", detect_launchd_deplatformized),
    ];
    BOOL clean = YES;
    for (NSDictionary *check in checks) clean = clean && [check[@"passed"] boolValue];
    SHDWRunnerFinish(@"roothider", @"Roothider JailbreakDetector", @"main@5b3d0be",
        clean ? @"clean" : @"jailbroken",
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
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(RoothiderAppDelegate.class));
    }
}
