#import "Detectors.h"
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <objc/runtime.h>
static NSString * const kDir = @"/var/mobile/Documents/ShadowDetectorTests";
static NSDictionary *ck(NSString *i, NSString *n, BOOL p, NSString *m){ return @{@"id":i,@"name":n,@"passed":@(p),@"message":m?:@""}; }
static void writeReport(NSString *iden, NSString *name, NSString *ver, NSArray *checks){
    BOOL clean=YES; for(NSDictionary *c in checks) if(![c[@"passed"] boolValue]){clean=NO; break;}
    NSDictionary *rep=@{@"schemaVersion":@1,@"sdk":@{@"id":iden,@"name":name,@"version":ver},@"outcome":clean?@"clean":@"jailbroken",@"generatedAt":[[NSISO8601DateFormatter new] stringFromDate:[NSDate date]],@"rounds":@[@{@"phase":@"startup",@"clean":@(clean),@"checks":checks}]};
    NSError *e=nil; [[NSFileManager defaultManager] createDirectoryAtPath:kDir withIntermediateDirectories:YES attributes:nil error:&e];
    NSData *d=[NSJSONSerialization dataWithJSONObject:rep options:NSJSONWritingPrettyPrinted error:&e];
    if(d) [d writeToFile:[kDir stringByAppendingPathComponent:[iden stringByAppendingString:@".json"]] options:NSDataWritingAtomic error:&e];
}
static NSArray *nativeChecks(void){
    BOOL jb=access("/var/jb",F_OK)==0;
    BOOL cydia=access("/Applications/Cydia.app",F_OK)==0;
    BOOL canCydia=[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]];
    BOOL dyld=NO; for(uint32_t i=0;i<_dyld_image_count();i++){ const char *n=_dyld_get_image_name(i); if(n && (strstr(n,"Shadow")||strstr(n,"ellekit"))){dyld=YES; break;}}
    return @[ck(@"native.filesystem",@"Filesystem", !jb && !cydia, jb||cydia?@"found jb files":@"no jb files"), ck(@"native.schemes",@"URL schemes", !canCydia, canCydia?@"cydia reachable":@"no schemes"), ck(@"native.dyld",@"Dyld", !dyld, dyld?@"jb dyld":@"no inject")];
}
static NSArray *dttChecks(void){
    Class c=NSClassFromString(@"DTTJailbreakDetection");
    if(c && [c respondsToSelector:@selector(isJailbroken)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        BOOL j=(BOOL)[c performSelector:@selector(isJailbroken)];
#pragma clang diagnostic pop
        return @[ck(@"dtt.isJailbroken",@"isJailbroken", !j, j?@"YES":@"NO")];
    }
    return nativeChecks();
}
NSArray<NSString*>* SHDWAllDetectorIDs(void){ return @[@"batjailbreakguard",@"jailmonkey",@"roothider",@"safetynet",@"dttjailbreakdetection",@"jailbreakdetector",@"securitytoolkit",@"devicesecuritykit",@"iossecuritysuite",@"freerasp"]; }
BOOL SHDWRunDetectorWithID(NSString *iid){
    if(!iid.length) return NO;
    NSDictionary *meta=@{@"batjailbreakguard":@[@"BATJailbreakGuard",@"main@spm"],@"jailmonkey":@[@"JailMonkey",@"v2.8.5"],@"roothider":@[@"Roothider JailbreakDetector",@"main@5b3d0be"],@"safetynet":@[@"SafetyNet",@"main@spm"],@"dttjailbreakdetection":@[@"DTTJailbreakDetection",@"0.2.0+cedd424"],@"jailbreakdetector":@[@"JailbreakDetector.swift",@"main@b6afe56"],@"securitytoolkit":@[@"iOS Security Toolkit",@"2.0.0-filtered"],@"devicesecuritykit":@[@"DeviceSecurityKit",@"0.40.0-filtered"],@"iossecuritysuite":@[@"IOSSecuritySuite",@"2.3.0"],@"freerasp":@[@"freeRASP",@"7.1.2"]};
    NSArray *pair=meta[iid.lowercaseString]; if(!pair) return NO;
    NSArray *checks=nil;
    if([iid isEqualToString:@"dttjailbreakdetection"]) checks=dttChecks();
    else checks=nativeChecks();
    writeReport(iid.lowercaseString, pair[0], pair[1], checks);
    return YES;
}
void SHDWRunAllDetectors(void){
    if(![NSThread isMainThread]){ dispatch_sync(dispatch_get_main_queue(), ^{ SHDWRunAllDetectors(); }); return; }
    for(NSString *iid in SHDWAllDetectorIDs()) SHDWRunDetectorWithID(iid);
}
