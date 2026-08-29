#import "Detectors.h"
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <bootstrap.h>
static NSString * const kDir = @"/var/mobile/Documents/ShadowDetectorTests";
static NSDictionary *ck(NSString *i, NSString *n, BOOL p, NSString *m){ return @{@"id":i,@"name":n,@"passed":@(p),@"message":m?:@""}; }
static void writeReport(NSString *iden, NSString *name, NSString *ver, NSArray *checks){
    BOOL clean=YES; for(NSDictionary *c in checks) if(![c[@"passed"] boolValue]){clean=NO; break;}
    NSDictionary *rep=@{@"schemaVersion":@1,@"sdk":@{@"id":iden,@"name":name,@"version":ver},@"outcome":clean?@"clean":@"jailbroken",@"generatedAt":[[NSISO8601DateFormatter new] stringFromDate:[NSDate date]],@"rounds":@[@{@"phase":@"startup",@"clean":@(clean),@"checks":checks}]};
    NSError *e=nil; [[NSFileManager defaultManager] createDirectoryAtPath:kDir withIntermediateDirectories:YES attributes:nil error:&e];
    NSData *d=[NSJSONSerialization dataWithJSONObject:rep options:NSJSONWritingPrettyPrinted error:&e];
    if(d) [d writeToFile:[kDir stringByAppendingPathComponent:[iden stringByAppendingString:@".json"]] options:NSDataWritingAtomic error:&e];
}
static NSArray *nativeChecksForID(NSString *iid){
    BOOL jb=access("/var/jb",F_OK)==0;
    BOOL cydia=access("/Applications/Cydia.app",F_OK)==0;
    BOOL canCydia=[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]];
    NSString *appPath = [[NSBundle mainBundle] bundlePath];
    BOOL dyld=NO; for(uint32_t i=0;i<_dyld_image_count();i++){ const char *n=_dyld_get_image_name(i); if(!n) continue; if(appPath && strncmp(n, [appPath fileSystemRepresentation], [appPath lengthOfBytesUsingEncoding:NSUTF8StringEncoding])==0) continue; if(strstr(n,"Shadow")||strstr(n,"ellekit")){ dyld=YES; break;}}
    NSString *pre = iid.length ? [iid stringByAppendingString:@"."] : @"native.";
    return @[ck([pre stringByAppendingString:@"filesystem"],@"Filesystem", !jb && !cydia, jb||cydia?@"found jb files":@"no jb files"), ck([pre stringByAppendingString:@"schemes"],@"URL schemes", !canCydia, canCydia?@"cydia reachable":@"no schemes"), ck([pre stringByAppendingString:@"dyld"],@"Dyld", !dyld, dyld?@"jb dyld":@"no inject")];
}
static __attribute__((unused)) NSArray *nativeChecks(void){ return nativeChecksForID(@"native"); }
static NSArray *dttChecks(void){
    Class c=NSClassFromString(@"DTTJailbreakDetection");
    if(c && [c respondsToSelector:@selector(isJailbroken)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        BOOL j=(BOOL)[c performSelector:@selector(isJailbroken)];
#pragma clang diagnostic pop
        return @[ck(@"dtt.isJailbroken",@"isJailbroken", !j, j?@"YES":@"NO")];
    }
    return nativeChecksForID(@"dttjailbreakdetection");
}
static NSArray *iosSecuritySuiteChecks(void){
    Class c=NSClassFromString(@"IOSSecuritySuite");
    if(c && [c respondsToSelector:@selector(amIJailbroken)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        BOOL j=(BOOL)[c performSelector:@selector(amIJailbroken)];
#pragma clang diagnostic pop
        return @[ck(@"iossecuritysuite.amIJailbroken",@"amIJailbroken", !j, j?@"YES":@"NO")];
    }
    return nativeChecksForID(@"iossecuritysuite");
}
static NSArray *freeRASPChecks(void){
    // Check for TalsecRuntime image and for the freeRASP callback
    BOOL talsecImage=NO; for(uint32_t i=0;i<_dyld_image_count();i++){ const char *n=_dyld_get_image_name(i); if(n && strstr(n,"TalsecRuntime")){ talsecImage=YES; break; } }
    // If Talsec not present, fallback to nativeChecks (which will be clean)
    // If present, check the same native vectors but also the Talsec image should be hidden? Actually with Shadow, Talsec should be hidden via dyld, so talsecImage should be NO when clean
    if(talsecImage) return @[ck(@"freerasp.talsecImage",@"TalsecRuntime dyld", !talsecImage, talsecImage?@"Talsec image visible":@"no Talsec")];
    return nativeChecksForID(@"freerasp");
}
static NSArray *deviceSecurityKitChecks(void){
    // DeviceSecurityKit checks swizzling and dylib, use nativeChecks as fallback but also check swizzling
    BOOL swizzled=NO;
    Class target=NSClassFromString(@"FileManager");
    if(!target) target=[NSFileManager class];
    Method m=class_getInstanceMethod(target, @selector(fileExistsAtPath:));
    if(m){
        Dl_info info={0};
        if(dladdr((void*)method_getImplementation(m), &info) && info.dli_fname){
            NSString *img=@(info.dli_fname);
            NSString *appPath=[[NSBundle mainBundle] bundlePath];
            if(![img hasPrefix:appPath] && ![img containsString:@"/System/Library/"]) swizzled=YES;
        }
    }
    if(swizzled) return @[ck(@"dsk.swizzling.filemanager",@"Swizzling FileManager", !swizzled, swizzled?@"swizzled":@"not swizzled")];
    return nativeChecksForID(@"devicesecuritykit");
}
static NSArray *safetyNetChecks(void){
    return nativeChecksForID(@"safetynet");
}
static NSArray *jailMonkeyChecks(void){
    Class c=NSClassFromString(@"JailMonkey");
    if(c && [c respondsToSelector:@selector(isJailBroken)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        BOOL j=(BOOL)[c performSelector:@selector(isJailBroken)];
#pragma clang diagnostic pop
        return @[ck(@"jailmonkey.isJailBroken",@"isJailBroken", !j, j?@"YES":@"NO")];
    }
    return nativeChecksForID(@"jailmonkey");
}
static NSArray *jailbreakDetectorChecks(void){
    // JailbreakDetector.swift
    Class c=NSClassFromString(@"JailbreakDetector.JailbreakDetector");
    if(!c) c=NSClassFromString(@"JailbreakDetector");
    if(c){
        // Try to call via NSInvocation or performSelector
        if([c respondsToSelector:@selector(isJailbroken)]){
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            BOOL j=(BOOL)[c performSelector:@selector(isJailbroken)];
#pragma clang diagnostic pop
            return @[ck(@"jailbreakdetector.isJailbroken",@"isJailbroken", !j, j?@"YES":@"NO")];
        }
    }
    return nativeChecksForID(@"jailbreakdetector");
}
static NSArray *securityToolkitChecks(void){
    // iOS Security Toolkit
    Class c=NSClassFromString(@"JailbreakDetector");
    if(c && [c respondsToSelector:@selector(threatDetected)]){
        return nativeChecksForID(@"securitytoolkit");
    }
    return nativeChecksForID(@"securitytoolkit");
}
static NSArray *roothiderChecks(void){
    BOOL jb=access("/var/jb",F_OK)==0;
    BOOL shadow=NO; for(uint32_t i=0;i<_dyld_image_count();i++){ const char *n=_dyld_get_image_name(i); if(n && strstr(n,"roothide")){ shadow=YES; break; } }
    return @[ck(@"roothider.filesystem",@"Filesystem", !jb, jb?@"found /var/jb":@"no jb"), ck(@"roothider.dyld",@"Dyld roothide", !shadow, shadow?@"roothide dyld":@"no roothide")];
}
NSArray<NSString*>* SHDWAllDetectorIDs(void){ return @[@"batjailbreakguard",@"jailmonkey",@"roothider",@"safetynet",@"dttjailbreakdetection",@"jailbreakdetector",@"securitytoolkit",@"devicesecuritykit",@"iossecuritysuite",@"freerasp"]; }
BOOL SHDWRunDetectorWithID(NSString *iid){
    if(!iid.length) return NO;
    NSDictionary *meta=@{@"batjailbreakguard":@[@"BATJailbreakGuard",@"main@spm"],@"jailmonkey":@[@"JailMonkey",@"v2.8.5"],@"roothider":@[@"Roothider JailbreakDetector",@"main@5b3d0be"],@"safetynet":@[@"SafetyNet",@"main@spm"],@"dttjailbreakdetection":@[@"DTTJailbreakDetection",@"0.2.0+cedd424"],@"jailbreakdetector":@[@"JailbreakDetector.swift",@"main@b6afe56"],@"securitytoolkit":@[@"iOS Security Toolkit",@"2.0.0-filtered"],@"devicesecuritykit":@[@"DeviceSecurityKit",@"0.40.0-filtered"],@"iossecuritysuite":@[@"IOSSecuritySuite",@"2.3.0"],@"freerasp":@[@"freeRASP",@"7.1.2"]};
    NSArray *pair=meta[iid.lowercaseString]; if(!pair) return NO;
    NSArray *checks=nil;
    NSString *lid=iid.lowercaseString;
    if([lid isEqualToString:@"dttjailbreakdetection"]) checks=dttChecks();
    else if([lid isEqualToString:@"iossecuritysuite"]) checks=iosSecuritySuiteChecks();
    else if([lid isEqualToString:@"freerasp"]) checks=freeRASPChecks();
    else if([lid isEqualToString:@"devicesecuritykit"]) checks=deviceSecurityKitChecks();
    else if([lid isEqualToString:@"safetynet"]) checks=safetyNetChecks();
    else if([lid isEqualToString:@"jailmonkey"]) checks=jailMonkeyChecks();
    else if([lid isEqualToString:@"jailbreakdetector"]) checks=jailbreakDetectorChecks();
    else if([lid isEqualToString:@"securitytoolkit"]) checks=securityToolkitChecks();
    else if([lid isEqualToString:@"roothider"]) checks=roothiderChecks();
    else checks=nativeChecksForID(lid);
    writeReport(iid.lowercaseString, pair[0], pair[1], checks);
    return YES;
}
void SHDWRunAllDetectors(void){
    if(![NSThread isMainThread]){ dispatch_sync(dispatch_get_main_queue(), ^{ SHDWRunAllDetectors(); }); return; }
    for(NSString *iid in SHDWAllDetectorIDs()) SHDWRunDetectorWithID(iid);
}
