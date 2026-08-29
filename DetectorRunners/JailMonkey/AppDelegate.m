#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
// ponytail: native JailMonkey vectors — file, scheme, write, dyld — no RN bridge needed

@interface JailMonkeyAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic, strong) UILabel *label;
@property(nonatomic, strong) NSDate *lastRun;
@end

static NSDictionary *check(NSString *cid, NSString *name, BOOL passed, NSString *msg){ return @{@"id":cid,@"name":name,@"passed":@(passed),@"message":msg}; }

@implementation JailMonkeyAppDelegate
- (void)run:(UIApplication*)app{
    if(self.lastRun && -self.lastRun.timeIntervalSinceNow < 2) return;
    self.lastRun=[NSDate date];
    NSMutableArray *checks=[NSMutableArray new];
    // JailMonkey: isJailBroken (file existence)
    BOOL cydiaAccess = access("/Applications/Cydia.app",F_OK)==0;
    [checks addObject:check(@"jailmonkey.file.cydia",@"Cydia.app exists", !cydiaAccess, cydiaAccess?@"found Cydia":@"no Cydia")];
    BOOL substrateAccess = access("/Library/MobileSubstrate/MobileSubstrate.dylib",F_OK)==0;
    [checks addObject:check(@"jailmonkey.file.substrate",@"MobileSubstrate exists", !substrateAccess, substrateAccess?@"found substrate":@"no substrate")];
    BOOL bashAccess = access("/bin/bash",F_OK)==0;
    [checks addObject:check(@"jailmonkey.file.bash",@"bash exists", !bashAccess, bashAccess?@"found bash":@"no bash")];
    BOOL sftpAccess = access("/usr/libexec/sftp-server",F_OK)==0;
    [checks addObject:check(@"jailmonkey.file.sftp",@"sftp-server exists", !sftpAccess, sftpAccess?@"found sftp":@"no sftp")];
    // NSFileManager variant (second signal, same paths)
    BOOL cydiaFM = [[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"];
    [checks addObject:check(@"jailmonkey.filemanager",@"FileManager Cydia", !cydiaFM, cydiaFM?@"fileExists YES":@"NO")];
    // canOpenURL cydia://
    BOOL canOpen = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]];
    [checks addObject:check(@"jailmonkey.scheme",@"cydia:// scheme", !canOpen, canOpen?@"reachable":@"not reachable")];
    // canOpen sileo/zbra for RN parity
    BOOL canOpenSileo = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"sileo://package/com.example.package"]];
    [checks addObject:check(@"jailmonkey.scheme.sileo",@"sileo:// scheme", !canOpenSileo, canOpenSileo?@"reachable":@"not reachable")];
    // write outside sandbox (/private)
    NSError *err=nil; NSString *p=@"/private/jailmonkey.txt"; [@"." writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&err];
    BOOL canWrite = err==nil; if(canWrite) [[NSFileManager defaultManager] removeItemAtPath:p error:nil];
    [checks addObject:check(@"jailmonkey.write",@"Write /private", !canWrite, canWrite?@"wrote outside sandbox":@"sandbox intact")];
    // dyld (JailMonkey also checks via ObjC)
    BOOL dyldFound=NO; NSString *hit=nil; for(uint32_t i=0;i<_dyld_image_count();i++){ const char *n=_dyld_get_image_name(i); if(n){ NSString *s=@(n); if([s.lowercaseString containsString:@"substrate"]||[s.lowercaseString containsString:@"cynject"]||[s.lowercaseString containsString:@"libhooker"]){ dyldFound=YES; hit=s; break; } } }
    [checks addObject:check(@"jailmonkey.dyld",@"Dyld injected", !dyldFound, dyldFound?hit:@"no inject")];
    // trust fall (RN) — canMockLocation placeholder (always clean on iOS without dev)
    [checks addObject:check(@"jailmonkey.trustfall",@"TrustFall (mock location)", YES, @"not mocked")];

    BOOL clean=YES; for(NSDictionary *c in checks) if(![c[@"passed"] boolValue]) clean=NO;
    NSString *outcome=clean?@"clean":@"jailbroken";
    NSDictionary *report=@{@"schemaVersion":@1,@"sdk":@{@"id":@"jailmonkey",@"name":@"JailMonkey",@"version":@"v2.8.5"},@"outcome":outcome,@"generatedAt":[NSISO8601DateFormatter.new stringFromDate:self.lastRun],@"rounds":@[@{@"phase":@"startup",@"clean":@(clean),@"checks":checks}]};
    NSString *dir=@"/var/mobile/Documents/ShadowDetectorTests"; NSError *e=nil; [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&e];
    NSData *d=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&e]; BOOL ok=d && [d writeToFile:[dir stringByAppendingPathComponent:@"jailmonkey.json"] options:NSDataWritingAtomic error:&e];
    if(!ok) self.label.text=[NSString stringWithFormat:@"Report failed\n%@", e.localizedDescription]; else self.label.text=clean?@"JailMonkey clean":@"JailMonkey jailbroken";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{ [app openURL:[NSURL URLWithString:@"shadow-detectors://refresh"] options:@{} completionHandler:nil]; });
}
- (BOOL)application:(UIApplication*)a didFinishLaunchingWithOptions:(NSDictionary*)o{
    UIViewController *c=[UIViewController new]; c.view.backgroundColor=UIColor.systemBackgroundColor;
    self.label=[[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds,24,24)]; self.label.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight; self.label.font=[UIFont preferredFontForTextStyle:UIFontTextStyleTitle2]; self.label.numberOfLines=0; self.label.textAlignment=NSTextAlignmentCenter; self.label.text=@"Running JailMonkey…"; [c.view addSubview:self.label];
    self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds]; self.window.rootViewController=c; [self.window makeKeyAndVisible]; [self run:a]; return YES;
}
- (void)applicationDidBecomeActive:(UIApplication*)a{ [self run:a]; }
- (BOOL)application:(UIApplication*)a openURL:(NSURL*)u options:(NSDictionary*)o{ [self run:a]; return YES; }
@end
int main(int argc,char *argv[]){ @autoreleasepool{ return UIApplicationMain(argc,argv,nil,NSStringFromClass(JailMonkeyAppDelegate.class)); } }
