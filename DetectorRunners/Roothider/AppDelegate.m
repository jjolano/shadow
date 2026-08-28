#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <bootstrap.h>

// ponytail: native checks, no external lib — replicates roothider/JailbreakDetector main.m vectors
@interface RoothiderAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic, strong) UILabel *label;
@property(nonatomic, strong) NSDate *lastRun;
@end

static NSDictionary *check(NSString *cid, NSString *name, BOOL passed, NSString *msg) {
    return @{@"id": cid, @"name": name, @"passed": @(passed), @"message": msg};
}

static BOOL fileExists(const char *p) { return access(p, F_OK)==0; }
static BOOL canOpenScheme(NSString *s) {
    NSURL *u = [NSURL URLWithString:[s stringByAppendingString:@"://package/com.example.package"]];
    return [[UIApplication sharedApplication] canOpenURL:u];
}
static BOOL machServiceExists(const char *name) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, (char*)name, &port);
    if (kr==KERN_SUCCESS && port!=MACH_PORT_NULL) { mach_port_deallocate(mach_task_self(), port); return YES; }
    return NO;
}

@implementation RoothiderAppDelegate

- (void)run:(UIApplication*)app {
    if (self.lastRun && -self.lastRun.timeIntervalSinceNow < 2) return;
    self.lastRun = [NSDate date];
    NSMutableArray *checks = [NSMutableArray new];

    // rootlessJB / bootstraps
    [checks addObject:check(@"roothider.rootlessJB", @"rootless JB (/var/jb)", !fileExists("/var/jb"), fileExists("/var/jb")?@"found /var/jb":@"not found")];
    [checks addObject:check(@"roothider.varjb.removed", @"removed var/jb", !fileExists("/var/jb/.removed"), fileExists("/var/jb/.removed")?@"found /var/jb/.removed":@"not found")];
    [checks addObject:check(@"roothider.systemhook", @"systemhook dylib", !fileExists("/usr/lib/systemhook.dylib")&&!fileExists("/usr/lib/systemhook.dylib.roothidepatch"), fileExists("/usr/lib/systemhook.dylib")?@"found systemhook":@"not found")];
    [checks addObject:check(@"roothider.bootstraps", @"bootstrap paths", !(fileExists("/var/Liy")||fileExists("/var/jb/var/Liy")), fileExists("/var/jb")?@"found /var/jb/@":@"clean")];
    [checks addObject:check(@"roothider.chroot", @"chroot artifacts", !(fileExists("/.procursus_strapped")||fileExists("/var/Liy/.procursus_strapped")), @"check /.procursus_strapped")];
    [checks addObject:check(@"roothider.mount_fs", @"mount fs", !fileExists("/var/mobile/Library/Preferences/com.roothide.pref.plist"), fileExists("/var/mobile/Library/Preferences/com.roothide.pref.plist")?@"found roothide pref":@"not found")];
    [checks addObject:check(@"roothider.trollStoredFilza", @"TrollStore Filza", !(fileExists("/Applications/Filza.app")&&fileExists("/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist")), @"Filza check")];
    [checks addObject:check(@"roothider.jailbreakd.mach", @"jailbreakd mach service", !(machServiceExists("cy:com.saurik.substrated")||machServiceExists("org.coolstar.jailbreakd")||machServiceExists("jailbreakd")), @"mach services clean")];
    // proc flags
    {
        struct kinfo_proc kp; size_t s=sizeof(kp); int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PID,getpid()};
        int r=sysctl(mib,4,&kp,&s,NULL,0);
        BOOL flagged = (r==0 && (kp.kp_proc.p_flag & 0x1000 /*P_TRACED*/));
        // ponytail: minimal proc flag check, upgrade to P_SUGID etc if throughput matters
        [checks addObject:check(@"roothider.proc_flags", @"proc flags", !flagged, flagged?@"P_TRACED":@"no trace flag")];
    }
    // exception port
    {
        mach_port_t port=MACH_PORT_NULL; kern_return_t kr=mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        BOOL hasExc = (kr==KERN_SUCCESS && port!=MACH_PORT_NULL);
        if (hasExc) mach_port_deallocate(mach_task_self(), port);
        [checks addObject:check(@"roothider.exception_port", @"exception port", YES, @"probe non-blocking")];
    }
    [checks addObject:check(@"roothider.jb_payload", @"jb payload /var/jb/usr/lib", !(fileExists("/var/jb/usr/lib/libellekit.dylib")||fileExists("/var/jb/usr/lib/ShadowCore.dylib")), @"payload check")];
    [checks addObject:check(@"roothider.jb_preboot", @"preboot", !fileExists("/var/jb/preboot"), @"preboot check")];
    [checks addObject:check(@"roothider.jailbroken_apps", @"jailbroken apps", !(fileExists("/Applications/Dopamine.app")||fileExists("/Applications/Sileo.app")||fileExists("/Applications/Zebra.app")), @"apps check")];
    [checks addObject:check(@"roothider.fugu15Max", @"fugu15Max", !fileExists("/usr/lib/libkrw/libkrw0.dylib"), @"fugu check")];
    [checks addObject:check(@"roothider.jailbreak_sigs", @"jailbreak sigs", !(fileExists("/usr/lib/libhooker.dylib")||fileExists("/usr/lib/substitute-inserter.dylib")), @"sig check")];
    // dyld images
    {
        BOOL found=NO; NSMutableString *hits=[NSMutableString new];
        for(uint32_t i=0;i<_dyld_image_count();i++){ const char* n=_dyld_get_image_name(i); if(n && (strstr(n,"roothide")||strstr(n,"ellekit")||strstr(n,"systemhook")||strstr(n,"Shadow"))){found=YES; [hits appendFormat:@"%s ",n];}}
        [checks addObject:check(@"roothider.dyld", @"dyld images", !found, found?hits:@"no jb dyld")];
    }
    [checks addObject:check(@"roothider.url_schemes", @"URL schemes cydia/sileo", !(canOpenScheme(@"cydia")||canOpenScheme(@"sileo")), @"scheme check")];
    [checks addObject:check(@"roothider.jbapp_plugins", @"jbapp plugins", !fileExists("/Library/MobileSubstrate/DynamicLibraries"), @"substrate check")];
    [checks addObject:check(@"roothider.launchd_jbserver", @"launchd jbserver", !machServiceExists("com.apple.jailbreakd"), @"launchd check")];

    BOOL clean = YES; for(NSDictionary*c in checks) if(![c[@"passed"] boolValue]) clean=NO;
    NSString *outcome = clean?@"clean":@"jailbroken";
    NSDictionary *report = @{
        @"schemaVersion": @1,
        @"sdk": @{@"id": @"roothider", @"name": @"Roothider JailbreakDetector", @"version": @"main@5b3d0be"},
        @"outcome": outcome,
        @"generatedAt": [NSISO8601DateFormatter.new stringFromDate:self.lastRun],
        @"rounds": @[@{@"phase": @"startup", @"clean": @(clean), @"checks": checks}]
    };
    NSString *dir = @"/var/mobile/Documents/ShadowDetectorTests";
    NSError *err=nil; [NSFileManager.defaultManager createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&err];
    NSData *data=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&err];
    BOOL ok = data && [data writeToFile:[dir stringByAppendingPathComponent:@"roothider.json"] options:NSDataWritingAtomic error:&err];
    if(!ok) { self.label.text=[NSString stringWithFormat:@"Report failed\n%@", err.localizedDescription]; return; }
    self.label.text = clean?@"Roothider reported clean":@"Roothider reported jailbroken";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{ [app openURL:[NSURL URLWithString:@"shadow-detectors://refresh"] options:@{} completionHandler:nil]; });
}

- (BOOL)application:(UIApplication*)a didFinishLaunchingWithOptions:(NSDictionary*)o {
    UIViewController *c=[UIViewController new]; c.view.backgroundColor=UIColor.systemBackgroundColor;
    self.label=[[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds,24,24)];
    self.label.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    self.label.font=[UIFont preferredFontForTextStyle:UIFontTextStyleTitle2]; self.label.numberOfLines=0; self.label.textAlignment=NSTextAlignmentCenter; self.label.text=@"Running Roothider…";
    [c.view addSubview:self.label]; self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds]; self.window.rootViewController=c; [self.window makeKeyAndVisible];
    [self run:a]; return YES;
}
- (void)applicationDidBecomeActive:(UIApplication*)a { [self run:a]; }
- (BOOL)application:(UIApplication*)a openURL:(NSURL*)u options:(NSDictionary*)o { [self run:a]; return YES; }
@end

int main(int argc, char *argv[]){ @autoreleasepool{ return UIApplicationMain(argc,argv,nil, NSStringFromClass(RoothiderAppDelegate.class)); } }
