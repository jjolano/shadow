#import <DTTJailbreakDetection.h>
#import <UIKit/UIKit.h>

@interface DTTAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow* window;
@property(nonatomic, strong) UILabel* label;
@property(nonatomic, strong) NSDate* lastRun;
@end

@implementation DTTAppDelegate

- (void)run:(UIApplication*)application {
    if(self.lastRun && -self.lastRun.timeIntervalSinceNow < 2) return;
    self.lastRun = [NSDate date];
    BOOL jailbroken = [DTTJailbreakDetection isJailbroken];
    NSString* outcome = jailbroken ? @"jailbroken" : @"clean";
    NSDictionary* report = @{
        @"schemaVersion": @1,
        @"sdk": @{@"id": @"dttjailbreakdetection", @"name": @"DTTJailbreakDetection", @"version": @"0.2.0+cedd424"},
        @"outcome": outcome,
        @"generatedAt": [NSISO8601DateFormatter.new stringFromDate:self.lastRun],
        @"rounds": @[@{
            @"phase": @"startup",
            @"clean": @(!jailbroken),
            @"checks": @[@{
                @"id": @"dtt.isJailbroken",
                @"name": @"isJailbroken",
                @"passed": @(!jailbroken),
                @"message": jailbroken ? @"Library returned YES" : @"Library returned NO"
            }]
        }]
    };
    NSString* directory = @"/var/mobile/Documents/ShadowDetectorTests";
    NSError* error = nil;
    BOOL directoryReady = [NSFileManager.defaultManager createDirectoryAtPath:directory
        withIntermediateDirectories:YES attributes:nil error:&error];
    NSData* data = directoryReady ? [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted error:&error] : nil;
    BOOL written = data && [data writeToFile:[directory stringByAppendingPathComponent:@"dttjailbreakdetection.json"]
        options:NSDataWritingAtomic error:&error];
    if(!written) {
        self.label.text = [NSString stringWithFormat:@"Report write failed\n\n%@",
            error.localizedDescription ?: @"Unknown error"];
        return;
    }
    self.label.text = jailbroken ? @"DTTJailbreakDetection reported jailbroken" : @"DTTJailbreakDetection reported clean";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [application openURL:[NSURL URLWithString:@"shadow-detectors://refresh"] options:@{} completionHandler:nil];
    });
}

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)options {
    UIViewController* controller = [UIViewController new];
    controller.view.backgroundColor = UIColor.systemBackgroundColor;
    self.label = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 24, 24)];
    self.label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.label.adjustsFontForContentSizeCategory = YES;
    self.label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle2];
    self.label.numberOfLines = 0;
    self.label.textAlignment = NSTextAlignmentCenter;
    self.label.text = @"Running DTTJailbreakDetection…";
    [controller.view addSubview:self.label];
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];
    [self run:application];
    return YES;
}

- (void)applicationDidBecomeActive:(UIApplication*)application {
    [self run:application];
}

- (BOOL)application:(UIApplication*)application openURL:(NSURL*)url options:(NSDictionary*)options {
    [self run:application];
    return YES;
}

@end

int main(int argc, char* argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(DTTAppDelegate.class));
    }
}
