#import "Detectors.h"
#import "DetectorDashboard.h"
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import "JailMonkey.h"
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <spawn.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <bootstrap.h>

static NSString * const kDir = @"/var/mobile/Documents/ShadowDetectorTests";
static NSDictionary *ck(NSString *i, NSString *n, BOOL p, NSString *m){ return @{@"id":i,@"name":n,@"passed":@(p),@"message":m?:@""}; }
static NSDictionary *inconclusiveCheck(NSString *i, NSString *n, NSString *m){
    NSMutableDictionary *check=[ck(i,n,YES,m) mutableCopy];
    check[@"inconclusive"]=@YES;
    return check;
}
static NSDictionary *roundOf(NSString *phase, BOOL clean, NSArray *checks){ return @{@"phase":phase,@"clean":@(clean),@"checks":checks}; }
static uint64_t shdw_detector_framework_load_ns = 0;

static uint64_t shdw_detector_now_ns(void) {
    static mach_timebase_info_data_t timebase;
    if(timebase.denom == 0) mach_timebase_info(&timebase);
    uint64_t ticks = mach_continuous_time();
    return (ticks / timebase.denom) * timebase.numer +
        ((ticks % timebase.denom) * timebase.numer) / timebase.denom;
}

static NSDictionary *shdw_detector_timing(NSString *identifier, uint64_t elapsedNs) {
    static NSMutableDictionary *firstElapsed;
    static NSMutableDictionary *invocations;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        firstElapsed = [NSMutableDictionary new];
        invocations = [NSMutableDictionary new];
    });

    NSUInteger run = [invocations[identifier] unsignedIntegerValue] + 1;
    invocations[identifier] = @(run);
    NSNumber *first = firstElapsed[identifier];
    if(!first) {
        first = @(elapsedNs);
        firstElapsed[identifier] = first;
    }

    return @{
        @"clock" : @"mach_continuous_time",
        @"elapsed_ns" : @(elapsedNs),
        @"first_elapsed_ns" : first,
        @"run_index" : @(run),
        @"framework_load_ns" : @(shdw_detector_framework_load_ns),
    };
}

static NSDictionary *roundWithTiming(NSString *phase, BOOL clean, NSArray *checks, NSDictionary *timing) {
    NSMutableDictionary *round = [roundOf(phase, clean, checks) mutableCopy];
    round[@"elapsed_ns"] = timing[@"elapsed_ns"] ?: @0;
    round[@"check_count"] = @(checks.count);
    round[@"run_index"] = timing[@"run_index"] ?: @0;
    return round;
}

static void writeReport(NSString *iden, NSString *name, NSString *ver, NSArray *rounds, NSDictionary *harness, NSDictionary *timing){
    BOOL clean=YES;
    BOOL inconclusive=NO;
    for(NSDictionary *round in rounds){
        for(NSDictionary *check in round[@"checks"]){
            if([check[@"inconclusive"] boolValue]) inconclusive=YES;
            else if(![check[@"passed"] boolValue]) clean=NO;
        }
    }
    NSString *outcome=!clean?@"jailbroken":inconclusive?@"error":@"clean";
    NSString *forcedOutcome=[harness[@"outcome"] isKindOfClass:[NSString class]]?harness[@"outcome"]:nil;
    if(forcedOutcome.length) outcome=forcedOutcome;
    NSMutableDictionary *rep=[@{@"schemaVersion":@1,@"sdk":@{@"id":iden,@"name":name,@"version":ver},@"outcome":outcome,@"generatedAt":[[NSISO8601DateFormatter new] stringFromDate:[NSDate date]],@"rounds":rounds} mutableCopy];
    if(harness) rep[@"harness"]=harness;
    if(timing) rep[@"timing"]=timing;
    NSError *e=nil; [[NSFileManager defaultManager] createDirectoryAtPath:kDir withIntermediateDirectories:YES attributes:nil error:&e];
    NSData *d=[NSJSONSerialization dataWithJSONObject:rep options:NSJSONWritingPrettyPrinted error:&e];
    if(d) [d writeToFile:[kDir stringByAppendingPathComponent:[iden stringByAppendingString:@".json"]] options:NSDataWritingAtomic error:&e];
}
static BOOL fileExists(const char *p){ return access(p,F_OK)==0; }
@interface TalsecBridge : NSObject
+ (void)start;
+ (NSArray<NSString*>*)threats;
+ (BOOL)allChecksFinished;
@end

// Real Roothider detect_* functions (filtered main.m, see build script):
// findings are delivered through the redirected LOG macro.
static NSMutableArray *shdwRoothiderLogs(void){
    static NSMutableArray *logs; static dispatch_once_t once;
    dispatch_once(&once, ^{ logs=[NSMutableArray new]; });
    return logs;
}
void shdw_roothider_log(NSString *fmt, ...){
    va_list ap; va_start(ap, fmt);
    NSString *msg=[[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    @synchronized(shdwRoothiderLogs()){ [shdwRoothiderLogs() addObject:msg]; }
}
static NSUInteger shdwRoothiderMark(void){ @synchronized(shdwRoothiderLogs()){ return shdwRoothiderLogs().count; } }
static NSArray *shdwRoothiderSince(NSUInteger mark){
    @synchronized(shdwRoothiderLogs()){
        if(mark>=shdwRoothiderLogs().count) return @[];
        return [shdwRoothiderLogs() subarrayWithRange:NSMakeRange(mark, shdwRoothiderLogs().count-mark)];
    }
}
void detect_rootlessJB(void); void detect_kernBypass(void); void detect_chroot(void);
void detect_mount_fs(void); void detect_bootstraps(void); void detect_trollStoredFilza(void);
void detect_jailbreakd(void); void detect_proc_flags(void); void detect_jb_payload(void);
void detect_exception_port(void); void detect_jb_preboot(void); void detect_jailbroken_apps(void);
void detect_removed_varjb(void); void detect_fugu15Max(void); void detect_jailbreak_sigs(void);
void detect_jailbreak_port(void); void detect_cfprefsd_hook(void); void detect_bind_mounts(void);
void detect_launchd_ipchook(void); void detect_url_schemes(void);
static BOOL dyldHas(const char *needle){
    for(uint32_t i=0;i<_dyld_image_count();i++){ const char *n=_dyld_get_image_name(i); if(n && strstr(n,needle)) return YES; }
    return NO;
}
static id bridge(NSString *clsName, NSString *selName){
    Class c=NSClassFromString(clsName);
    if(!c || ![c respondsToSelector:NSSelectorFromString(selName)]) return nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    id r=[c performSelector:NSSelectorFromString(selName)];
#pragma clang diagnostic pop
    return r;
}
static id bridgeOnWorker(NSString *clsName, NSString *selName){
    if(![NSThread isMainThread]) return bridge(clsName,selName);
    __block id result=nil;
    dispatch_semaphore_t done=dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
        result=bridge(clsName,selName);
        dispatch_semaphore_signal(done);
    });
    while(dispatch_semaphore_wait(done,DISPATCH_TIME_NOW)!=0)
        [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    return result;
}
static BOOL bridgeBool(NSString *clsName, NSString *selName, NSArray *args){
    Class c=NSClassFromString(clsName);
    if(!c) return NO;
    SEL sel=NSSelectorFromString(selName);
    if(![c respondsToSelector:sel]) return NO;
    NSMethodSignature *sig=[c methodSignatureForSelector:sel];
    if(!sig) return NO;
    NSInvocation *inv=[NSInvocation invocationWithMethodSignature:sig];
    [inv setTarget:c]; [inv setSelector:sel];
    for(NSUInteger i=0;i<args.count;i++){
        id arg=args[i];
        [inv setArgument:&arg atIndex:(NSInteger)(2+i)];
    }
    [inv invoke];
    BOOL ret=NO;
    [inv getReturnValue:&ret];
    return ret;
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

static NSArray *dttChecks(void){
    Class c=NSClassFromString(@"DTTJailbreakDetection");
    if(c && [c respondsToSelector:@selector(isJailbroken)]){
        BOOL j=(BOOL)[c performSelector:@selector(isJailbroken)];
        return @[ck(@"dtt.isJailbroken",@"isJailbroken", !j, j?@"Library returned YES":@"Library returned NO")];
    }
    return nativeChecksForID(@"dttjailbreakdetection");
}

static NSArray *shadowProbeChecks(void){
    NSString *appPath=[[NSBundle mainBundle] bundlePath];
    BOOL bundleHidden=![[NSFileManager defaultManager] fileExistsAtPath:@"/Library/PreferenceBundles/ShadowPreferences.bundle"];
    BOOL prefsHidden=![[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
    NSMutableArray *imgs=[NSMutableArray new];
    for(uint32_t i=0;i<_dyld_image_count();i++){ const char *n=_dyld_get_image_name(i); if(!n) continue; NSString *s=@(n); if([s rangeOfString:@"shadow" options:NSCaseInsensitiveSearch].location!=NSNotFound && ![s hasPrefix:appPath]) [imgs addObject:s]; }
    Class ruleset=NSClassFromString(@"ShadowRuleset");
    BOOL methodHidden=ruleset==nil || class_getInstanceMethod(ruleset,NSSelectorFromString(@"internalDictionary"))==nil;
    return @[
        ck(@"shadow.path.bundle",@"Shadow preference bundle hidden", bundleHidden, bundleHidden?@"bundle hidden":@"bundle visible"),
        ck(@"shadow.path.preferences",@"Shadow preferences hidden", prefsHidden, prefsHidden?@"prefs hidden":@"prefs visible"),
        ck(@"shadow.dyld",@"Shadow images hidden", imgs.count==0, imgs.count==0?@"No Shadow image exposed":[imgs componentsJoinedByString:@"\n"]),
        ck(@"shadow.objc.class",@"ShadowRuleset hidden", ruleset==nil, ruleset==nil?@"objc_getClass returned nil":@"ShadowRuleset is visible"),
        ck(@"shadow.objc.method",@"internalDictionary hidden", methodHidden, methodHidden?@"method hidden":@"method visible"),
    ];
}

static NSArray *iosSecuritySuiteChecks(void){
    NSDictionary *jailbreakFailures=bridge(@"IOSSBridge",@"amIJailbrokenWithFailedChecks");
    if(!jailbreakFailures) return nativeChecksForID(@"iossecuritysuite");
    NSArray *jailbreakNames=@[@"urlSchemes",@"existenceOfSuspiciousFiles",@"suspiciousFilesCanBeOpened",@"restrictedDirectoriesWriteable",@"fork",@"symbolicLinks",@"dyld",@"suspiciousObjCClasses"];
    NSMutableArray *checks=[NSMutableArray new];
    for(NSString *name in jailbreakNames){
        NSString *msg=jailbreakFailures[name];
        [checks addObject:ck([@"iossecuritysuite.jailbreak." stringByAppendingString:name],[@"Jailbreak: " stringByAppendingString:name], msg==nil, msg?:@"Passed")];
    }
    NSDictionary *reverseFailures=bridge(@"IOSSBridge",@"amIReverseEngineeredWithFailedChecks");
    for(NSString *name in @[@"existenceOfSuspiciousFiles",@"dyld",@"openedPorts",@"pSelectFlag"]){
        NSString *msg=reverseFailures[name];
        [checks addObject:ck([@"iossecuritysuite.reverse." stringByAppendingString:name],[@"Reverse engineering: " stringByAppendingString:name], msg==nil, msg?:@"Passed")];
    }
    BOOL tampered=bridgeBool(@"IOSSBridge",@"amITamperedWithBundleID:",@[[[NSBundle mainBundle] bundleIdentifier] ?: @"me.jjolano.shadow.harness"]);
    [checks addObject:ck(@"iossecuritysuite.integrity.bundle",@"Bundle integrity", !tampered, tampered?@"Bundle identifier mismatch":@"Bundle identifier matches")];
    [checks addObject:ck(@"iossecuritysuite.debugger",@"Debugger", !bridgeBool(@"IOSSBridge",@"amIDebugged",@[]), @"Debugger not detected")];
    [checks addObject:ck(@"iossecuritysuite.parent",@"Unexpected parent", !bridgeBool(@"IOSSBridge",@"isParentPidUnexpected",@[]), @"Parent is launchd")];
    [checks addObject:ck(@"iossecuritysuite.emulator",@"Emulator", !bridgeBool(@"IOSSBridge",@"amIRunInEmulator",@[]), @"Physical device")];
    [checks addObject:ck(@"iossecuritysuite.proxy",@"Proxy or VPN", !bridgeBool(@"IOSSBridge",@"amIProxied",@[]), @"No proxy or VPN detected")];
    [checks addObject:ck(@"iossecuritysuite.lockdown",@"Lockdown mode", !bridgeBool(@"IOSSBridge",@"amIInLockdownMode",@[]), @"Lockdown mode disabled")];
    // ponytail: no amIRuntimeHooked/amIMSHooked/hasWatchpoint/hasBreakpoint —
    // those trigger the SDK's denyFishHook once-init, which SIGSEGVs while
    // patching images under Shadow's active dyld hooks. Re-add when the SDK
    // tolerates being loaded under an injected process.
    NSArray *exposed=bridge(@"IOSSBridge",@"suspiciousDylibs");
    [checks addObject:ck(@"iossecuritysuite.loadcommands",@"Suspicious load commands", exposed.count==0, exposed.count==0?@"No injected dylib exposed":[exposed componentsJoinedByString:@"\n"])];
    [checks addObjectsFromArray:shadowProbeChecks()];
    return checks;
}

static NSArray *jailbreakDetectorChecks(void){
    NSDictionary *result=bridge(@"JBDBridge",@"detectJailbreak");
    if(!result) return nativeChecksForID(@"jailbreakdetector");
    if(![result[@"jailbroken"] boolValue])
        return @[ck(@"jailbreakdetector.result",@"Jailbreak detection", YES, result[@"detail"]?:@"All configured checks passed")];
    NSArray *reasons=result[@"reasons"];
    NSMutableArray *checks=[NSMutableArray new];
    [reasons enumerateObjectsUsingBlock:^(NSString *reason,NSUInteger idx,BOOL *stop){
        [checks addObject:ck([NSString stringWithFormat:@"jailbreakdetector.failure.%lu",(unsigned long)idx],@"Jailbreak evidence", NO, reason)];
    }];
    return checks;
}

static NSArray *securityToolkitChecks(void){
    NSDictionary *statuses=bridge(@"STKBridge",@"statuses");
    Class stk=NSClassFromString(@"STKBridge");
    if(!stk) return nativeChecksForID(@"securitytoolkit");
    NSArray *probes=@[
        @{@"key":@"rootPrivileges",@"id":@"securitytoolkit.root_privileges",@"name":@"Root privileges"},
        @{@"key":@"hooks",@"id":@"securitytoolkit.hooks",@"name":@"Runtime hooks"},
        @{@"key":@"simulator",@"id":@"securitytoolkit.simulator",@"name":@"Simulator"},
        @{@"key":@"debugger",@"id":@"securitytoolkit.debugger",@"name":@"Debugger"},
        @{@"key":@"devicePasscode",@"id":@"securitytoolkit.device_passcode",@"name":@"Device passcode"},
        @{@"key":@"hardwareCryptography",@"id":@"securitytoolkit.hardware_cryptography",@"name":@"Hardware cryptography"},
    ];
    NSMutableArray *checks=[NSMutableArray new];
    for(NSDictionary *probe in probes){
        NSString *status=statuses[probe[@"key"]];
        BOOL detected=[status isEqualToString:@"present"];
        BOOL unknown=!status.length || [status hasPrefix:@"exception"] || [status isEqualToString:@"notChecked"];
        NSString *message=unknown?(status.length?status:@"No status returned"):(detected?@"Threat detected":@"No threat detected");
        [checks addObject:unknown?inconclusiveCheck(probe[@"id"],probe[@"name"],message):ck(probe[@"id"],probe[@"name"],!detected,message)];
    }
    return checks;
}

static NSArray *freeRASPChecks(BOOL *started, BOOL checksFinished){
    NSDictionary *threatNames=@{
        @"signature":@"appIntegrity", @"jailbreak":@"privilegedAccess", @"debugger":@"debug",
        @"runtimeManipulation":@"hooks", @"passcode":@"passcode", @"passcodeChange":@"passcodeChange",
        @"simulator":@"simulator", @"missingSecureEnclave":@"missingSecureEnclave", @"systemVPN":@"systemVPN",
        @"deviceChange":@"deviceBinding", @"deviceID":@"deviceID", @"unofficialStore":@"unofficialStore",
        @"screenshot":@"screenshot", @"screenRecording":@"screenRecording", @"timeSpoofing":@"timeSpoofing",
    };
    if(!NSClassFromString(@"TalsecBridge")) return nativeChecksForID(@"freerasp");
    if(!*started){ [TalsecBridge start]; *started=YES; }
    NSArray *threats=[TalsecBridge threats];
    NSMutableArray *checks=[NSMutableArray new];
    for(NSString *name in threatNames.allKeys){
        BOOL detected=[threats containsObject:threatNames[name]];
        NSString *identifier=[@"freerasp." stringByAppendingString:name];
        if(detected)
            [checks addObject:ck(identifier,name,NO,@"Threat callback received")];
        else if(checksFinished)
            [checks addObject:ck(identifier,name,YES,@"No threat callback")];
        else
            [checks addObject:inconclusiveCheck(identifier,name,@"No threat callback; checks incomplete")];
    }
    return checks;
}

// Real JailMonkey 2.8.5 (compiled in-process with RN bridge stubbed).
@interface JailMonkey (Harness)
- (BOOL)checkPaths; - (BOOL)checkSchemes; - (BOOL)canViolateSandbox; - (BOOL)canFork;
- (BOOL)checkSymlinks; - (BOOL)checkDylibs; - (BOOL)isDebugged; - (BOOL)isJailBroken;
- (BOOL)canMockLocation; - (NSString*)jailBrokenMessage;
@end

static NSArray *jailMonkeyChecks(void){
    JailMonkey *jm=[JailMonkey new];
    BOOL paths=[jm checkPaths];
    BOOL schemes=[jm checkSchemes];
    BOOL sandbox=[jm canViolateSandbox];
    BOOL fork=[jm canFork];
    BOOL symlinks=[jm checkSymlinks];
    BOOL dylibs=[jm checkDylibs];
    BOOL chain=paths||schemes||sandbox||fork||symlinks||dylibs;
    BOOL jailbroken=[jm isJailBroken];
    BOOL appOnMac=NO;
    if([[NSProcessInfo processInfo] respondsToSelector:@selector(isiOSAppOnMac)]) appOnMac=[NSProcessInfo processInfo].isiOSAppOnMac;
    Dl_info jmInfo={0};
    Method jmMethod=class_getInstanceMethod([jm class],@selector(isJailBroken));
    NSString *jmImp=jmMethod && dladdr((void*)method_getImplementation(jmMethod),&jmInfo) && jmInfo.dli_fname ? @(jmInfo.dli_fname) : @"?";
    NSString *isJBMsg=[NSString stringWithFormat:@"raw=%@; imp=%@", chain?@"jailbroken":@"clean", [jmImp containsString:@"ShadowCore"]?@"ShadowCore.dylib (hooked)":jmImp];
    return @[
        ck(@"jailmonkey.checkPaths",@"checkPaths (60+ paths)", !paths, paths?@"jailbreak file found":@"clean"),
        ck(@"jailmonkey.checkSchemes",@"checkSchemes (11 schemes)", !schemes, schemes?@"jailbreak scheme reachable":@"clean"),
        ck(@"jailmonkey.canViolateSandbox",@"canViolateSandbox", !sandbox, sandbox?@"wrote outside sandbox":@"sandbox intact"),
        ck(@"jailmonkey.canFork",@"canFork", !fork, fork?@"fork succeeded":@"fork denied"),
        ck(@"jailmonkey.checkSymlinks",@"checkSymlinks", !symlinks, symlinks?@"suspicious symlink":@"clean"),
        ck(@"jailmonkey.checkDylibs",@"checkDylibs (40+ dylibs)", !dylibs, dylibs?@"injected dylib":@"clean"),
        ck(@"jailmonkey.isDebugged",@"isDebugged", ![jm isDebugged], @"not debugged"),
        ck(@"jailmonkey.isiOSAppOnMac",@"isiOSAppOnMac (env)", !appOnMac, appOnMac?@"runtime reports iOS app on Mac":@"not on Mac"),
        ck(@"jailmonkey.isJailBroken",@"isJailBroken", !jailbroken, isJBMsg),
        ck(@"jailmonkey.canMockLocation",@"canMockLocation (RN)", ![jm canMockLocation], @"location not mocked"),
    ];
}

static NSArray *roothiderChecks(void){
    // Real roothider detect_* functions, each contributing its LOG findings as
    // one check. Fragile/private-API or side-effecting functions (launchd
    // xpc/guarded-port probes, passcode_status' Secure-Enclave test key,
    // LSApplicationWorkspace plugin scan) are intentionally not called.
    struct { const char *cid; const char *name; void (*fn)(void); } probes[] = {
        {"roothider.rootlessJB","rootlessJB",detect_rootlessJB},
        {"roothider.kernBypass","kernBypass",detect_kernBypass},
        {"roothider.chroot","chroot",detect_chroot},
        {"roothider.mount_fs","mount_fs",detect_mount_fs},
        {"roothider.bootstraps","bootstraps",detect_bootstraps},
        {"roothider.trollStoredFilza","trollStoredFilza",detect_trollStoredFilza},
        {"roothider.jailbreakd","jailbreakd",detect_jailbreakd},
        {"roothider.proc_flags","proc_flags",detect_proc_flags},
        {"roothider.jb_payload","jb_payload",detect_jb_payload},
        {"roothider.exception_port","exception_port",detect_exception_port},
        {"roothider.jb_preboot","jb_preboot",detect_jb_preboot},
        {"roothider.jailbroken_apps","jailbroken_apps",detect_jailbroken_apps},
        {"roothider.removed_varjb","removed_varjb",detect_removed_varjb},
        {"roothider.fugu15Max","fugu15Max",detect_fugu15Max},
        {"roothider.jailbreak_sigs","jailbreak_sigs",detect_jailbreak_sigs},
        {"roothider.jailbreak_port","jailbreak_port",detect_jailbreak_port},
        {"roothider.cfprefsd_hook","cfprefsd_hook",detect_cfprefsd_hook},
        {"roothider.bind_mounts","bind_mounts",detect_bind_mounts},
        {"roothider.launchd_ipchook","launchd_ipchook",detect_launchd_ipchook},
        {"roothider.url_schemes","url_schemes",detect_url_schemes},
    };
    NSMutableArray *checks=[NSMutableArray new];
    NSUInteger n=sizeof(probes)/sizeof(probes[0]);
    for(NSUInteger i=0;i<n;i++){
        NSUInteger mark=shdwRoothiderMark();
        probes[i].fn();
        if(i==n-1) [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        NSArray *found=shdwRoothiderSince(mark);
        [checks addObject:ck(@(probes[i].cid),@(probes[i].name), found.count==0, found.count?[found componentsJoinedByString:@"; "]:@"clean")];
    }
    return checks;
}

static NSArray *safetyNetChecks(void){
    // Real SafetyNet (framework; async actor bridged via SafetyNetBridge).
    if(!NSClassFromString(@"SafetyNetBridge")) return nativeChecksForID(@"safetynet");
    NSDictionary *result=bridgeOnWorker(@"SafetyNetBridge",@"runChecks");
    if(!result) return nativeChecksForID(@"safetynet");
    NSString *error=[result[@"error"] isKindOfClass:[NSString class]]?result[@"error"]:nil;
    if(error.length) return @[inconclusiveCheck(@"safetynet.result",@"SafetyNet result",error)];
    NSInteger level=[result[@"level"] integerValue];
    NSArray *reasons=result[@"reasons"];
    NSDictionary *map=@{
        @"jb_filesystem":@[@"safetynet.filesystem",@"Filesystem (90+ paths)"],
        @"jb_dylib":@[@"safetynet.dylib",@"Injected dylib"],
        @"jb_frida_port":@[@"safetynet.frida_port",@"Frida port"],
        @"jb_sandbox":@[@"safetynet.sandbox_write",@"Sandbox breach"],
        @"jb_url_scheme":@[@"safetynet.url_schemes",@"URL schemes"],
        @"jb_suspicious_process":@[@"safetynet.process",@"Suspicious process"],
        @"jb_shadow_tweak":@[@"safetynet.shadow",@"Shadow tweak"],
        @"jb_symlinks":@[@"safetynet.symlinks",@"Non-standard symlinks"],
        @"jb_open_port":@[@"safetynet.open_port",@"Suspicious open port"],
        @"debugger_attached":@[@"safetynet.debugger",@"Debugger attached"],
        @"process_traced":@[@"safetynet.traced",@"Process traced"],
        @"watchpoint_detected":@[@"safetynet.watchpoint",@"Watchpoint"],
        @"p_select_flag":@[@"safetynet.pselect",@"P_SELECT flag"],
        @"codesig_invalid":@[@"safetynet.codesig",@"Code signature"],
        @"system_proxy":@[@"safetynet.proxy",@"System proxy"],
        @"vpn_detected":@[@"safetynet.vpn",@"VPN"],
    };
    NSMutableArray *checks=[NSMutableArray new];
    for(NSString *key in map){
        NSArray *pair=map[key];
        BOOL detected=[reasons containsObject:key];
        [checks addObject:ck(pair[0],pair[1], !detected, detected?@"Threat detected":@"clean")];
    }
    NSArray *levels=@[@"none",@"medium",@"high",@"critical"];
    if(level<0 || level>=(NSInteger)levels.count)
        [checks addObject:inconclusiveCheck(@"safetynet.level",@"Aggregate threat level",@"No aggregate threat level returned")];
    else
        [checks addObject:ck(@"safetynet.level",@"Aggregate threat level", level==0, levels[level])];
    return checks;
}

static NSArray *batChecks(void){
    // Real BATJailbreakGuard services (framework, 9 modular check services).
    if(!NSClassFromString(@"BATBridge")) return nativeChecksForID(@"batjailbreakguard");
    NSArray *probes=@[
        @{@"id":@"bat.filepath",@"name":@"FilePath",@"sel":@"filePath"},
        @{@"id":@"bat.symboliclinks",@"name":@"SymbolicLinks",@"sel":@"symbolicLinks"},
        @{@"id":@"bat.environmentvariables",@"name":@"EnvironmentVariables",@"sel":@"environmentVariables"},
        @{@"id":@"bat.dynamiclib",@"name":@"DynamicLib",@"sel":@"dynamicLib"},
        @{@"id":@"bat.sandboxed",@"name":@"SandboxedEnvironment",@"sel":@"sandboxedEnvironment"},
        @{@"id":@"bat.rootuser",@"name":@"RootUser",@"sel":@"rootUser"},
        @{@"id":@"bat.openports",@"name":@"OpenPorts",@"sel":@"openPorts"},
        @{@"id":@"bat.preventedapis",@"name":@"PreventedAPIs",@"sel":@"preventedAPIs"},
        @{@"id":@"bat.checksum",@"name":@"Checksum",@"sel":@"checksum"},
    ];
    NSMutableArray *checks=[NSMutableArray new];
    for(NSDictionary *probe in probes){
        BOOL detected=bridgeBool(@"BATBridge",probe[@"sel"],@[]);
        if([probe[@"sel"] isEqualToString:@"checksum"])
            [checks addObject:inconclusiveCheck(probe[@"id"],probe[@"name"],@"No expected file checksums configured")];
        else
            [checks addObject:ck(probe[@"id"],probe[@"name"], !detected, detected?@"Threat detected":@"No threat detected")];
    }
    return checks;
}

static NSArray *deviceSecurityKitChecks(void){
    // Real DeviceSecurityKit detectors (framework; signature-update manager
    // stubbed — see detector-frameworks/stubs).
    if(!NSClassFromString(@"DSKBridge")) return nativeChecksForID(@"devicesecuritykit");
    if([[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){15,0,0}]){} else { return @[ck(@"dsk.gated",@"iOS version", NO, @"Requires iOS 15")]; }
    NSMutableArray *checks=[NSMutableArray new];
    BOOL jailbroken=bridgeBool(@"DSKBridge",@"isJailbroken",@[]);
    NSArray *evidence=bridge(@"DSKBridge",@"jailbreakEvidence");
    [checks addObject:ck(@"dsk.jailbreak",@"JailbreakDetector.isJailbroken", !jailbroken, jailbroken?(evidence.count?[evidence componentsJoinedByString:@", "]:@"detected"):@"clean")];
    [checks addObject:ck(@"dsk.hook.prologue",@"HookDetector.isFunctionHooked", !bridgeBool(@"DSKBridge",@"isFunctionHooked",@[]), @"function hook check")];
    [checks addObject:ck(@"dsk.swizzling",@"SwizzlingDetector.isSwizzled", !bridgeBool(@"DSKBridge",@"isSwizzled",@[]), @"swizzle check")];
    [checks addObject:ck(@"dsk.frida",@"FridaDetector.isFridaDetected", !bridgeBool(@"DSKBridge",@"isFridaDetected",@[]), @"frida check")];
    [checks addObject:ck(@"dsk.dylib",@"DylibInjectionDetector.isDylibInjected", !bridgeBool(@"DSKBridge",@"isDylibInjected",@[]), @"dylib check")];
    [checks addObject:ck(@"dsk.reverse",@"ReverseEngineeringDetector.isReverseEngineered", !bridgeBool(@"DSKBridge",@"isReverseEngineered",@[]), @"reverse-engineering check")];
    [checks addObject:ck(@"dsk.debugger",@"DebuggerDetector.isDebuggerAttached", !bridgeBool(@"DSKBridge",@"isDebuggerAttached",@[]), @"debugger check")];
    NSDictionary *emulator=bridge(@"DSKBridge",@"emulatorInfo");
    BOOL emulatorDetected=[emulator[@"detected"] boolValue];
    NSArray *methods=emulator[@"methods"];
    NSString *emulatorMessage=emulatorDetected?(methods.count?[methods componentsJoinedByString:@", "]:@"emulator detected"):@"physical device";
    [checks addObject:ck(@"dsk.emulator",@"EmulatorDetector.detectEmulator", !emulatorDetected, emulatorMessage)];
    return checks;
}

NSArray<NSString*>* SHDWAllDetectorIDs(void){ return @[@"batjailbreakguard",@"jailmonkey",@"roothider",@"safetynet",@"dttjailbreakdetection",@"jailbreakdetector",@"securitytoolkit",@"devicesecuritykit",@"iossecuritysuite",@"freerasp"]; }
static BOOL SHDWTalsecStarted=NO;
BOOL SHDWRunDetectorWithID(NSString *iid){
    if(!iid.length) return NO;
    NSDictionary *meta=@{@"batjailbreakguard":@[@"BATJailbreakGuard",@"main@spm"],@"jailmonkey":@[@"JailMonkey",@"v2.8.5"],@"roothider":@[@"Roothider JailbreakDetector",@"main@5b3d0be"],@"safetynet":@[@"SafetyNet",@"main@spm"],@"dttjailbreakdetection":@[@"DTTJailbreakDetection",@"0.2.0+cedd424"],@"jailbreakdetector":@[@"JailbreakDetector.swift",@"main@b6afe56"],@"securitytoolkit":@[@"iOS Security Toolkit",@"2.0.0"],@"devicesecuritykit":@[@"DeviceSecurityKit",@"0.40.0"],@"iossecuritysuite":@[@"IOSSecuritySuite",@"2.3.0"],@"freerasp":@[@"freeRASP",@"7.1.2"]};
    NSArray *pair=meta[iid.lowercaseString]; if(!pair) return NO;
    NSString *lid=iid.lowercaseString;
    if([lid isEqualToString:@"safetynet"]){
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            uint64_t start=shdw_detector_now_ns();
            NSArray *checks=safetyNetChecks();
            NSDictionary *timing=shdw_detector_timing(lid,shdw_detector_now_ns()-start);
            BOOL clean=YES; for(NSDictionary *c in checks) if(![c[@"passed"] boolValue]){ clean=NO; break; }
            writeReport(lid,pair[0],pair[1],@[roundWithTiming(@"startup",clean,checks,timing)],nil,timing);
            dispatch_async(dispatch_get_main_queue(), ^{
                [[NSNotificationCenter defaultCenter] postNotificationName:SHDWDetectorResultsChanged object:nil];
            });
        });
        return YES;
    }
    if([lid isEqualToString:@"freerasp"]){
        uint64_t start=shdw_detector_now_ns();
        BOOL checksFinished=[TalsecBridge allChecksFinished];
        NSArray *checks=freeRASPChecks(&SHDWTalsecStarted,checksFinished);
        NSDictionary *timing=shdw_detector_timing(lid,shdw_detector_now_ns()-start);
        BOOL clean=YES; for(NSDictionary *c in checks) if(![c[@"passed"] boolValue]){ clean=NO; break; }
        NSDictionary *harness=@{@"varJBVisible":@(fileExists("/var/jb")),@"shadowCoreVisible":@(fileExists("/var/jb/usr/lib/ShadowCore.dylib")),@"talsecStartReturned":@YES,@"talsecImageLoaded":@(dyldHas("TalsecRuntime")),@"talsecAllChecksFinished":@(checksFinished),@"outcome":@"running",@"stockMarkerVisibleBeforeStart":@(fileExists("/.file"))};
        writeReport(lid,pair[0],pair[1],@[roundWithTiming(@"startup",clean,checks,timing)],harness,timing);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(30*NSEC_PER_SEC)),dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            uint64_t settledStart=shdw_detector_now_ns();
            BOOL settledFinished=[TalsecBridge allChecksFinished];
            NSArray *settled=freeRASPChecks(&SHDWTalsecStarted,settledFinished);
            NSDictionary *settledTiming=shdw_detector_timing(lid,shdw_detector_now_ns()-settledStart);
            BOOL clean2=YES; for(NSDictionary *c in settled) if(![c[@"passed"] boolValue]){ clean2=NO; break; }
            NSMutableDictionary *h2=[harness mutableCopy];
            h2[@"talsecAllChecksFinished"]=@(settledFinished);
            [h2 removeObjectForKey:@"outcome"];
            if(!settledFinished && clean2) h2[@"outcome"]=@"error";
            writeReport(lid,pair[0],pair[1],@[roundWithTiming(@"settled",clean2,settled,settledTiming)],h2,settledTiming);
        });
        return YES;
    }
    uint64_t start=shdw_detector_now_ns();
    NSArray *checks=nil;
    if([lid isEqualToString:@"dttjailbreakdetection"]) checks=dttChecks();
    else if([lid isEqualToString:@"iossecuritysuite"]) checks=iosSecuritySuiteChecks();
    else if([lid isEqualToString:@"jailbreakdetector"]) checks=jailbreakDetectorChecks();
    else if([lid isEqualToString:@"securitytoolkit"]) checks=securityToolkitChecks();
    else if([lid isEqualToString:@"devicesecuritykit"]) checks=deviceSecurityKitChecks();
    else if([lid isEqualToString:@"jailmonkey"]) checks=jailMonkeyChecks();
    else if([lid isEqualToString:@"batjailbreakguard"]) checks=batChecks();
    else if([lid isEqualToString:@"roothider"]) checks=roothiderChecks();
    else checks=nativeChecksForID(lid);
    NSDictionary *timing=shdw_detector_timing(lid,shdw_detector_now_ns()-start);
    BOOL clean=YES; for(NSDictionary *c in checks) if(![c[@"passed"] boolValue]){ clean=NO; break; }
    writeReport(lid,pair[0],pair[1],@[roundWithTiming(@"startup",clean,checks,timing)],nil,timing);
    return YES;
}
static void shdw_dlopen_frameworks(void){
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        uint64_t start=shdw_detector_now_ns();
        // Resolve from the bundle's real (preboot) path: dlopen rejects the
        // /var/jb symlink form with "library not found" under the app sandbox.
        NSString *appFw=[[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"Frameworks"];
        for(NSString *n in @[@"IOSSecuritySuite",@"JailbreakDetector",@"SecurityToolkit",@"BATJailbreakGuard",@"DeviceSecurityKit"]){
            dlopen([[appFw stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.framework/%@",n,n]] fileSystemRepresentation], RTLD_NOW);
        }
        (void)NSClassFromString(@"IOSSBridge");
        (void)NSClassFromString(@"JBDBridge");
        (void)NSClassFromString(@"STKBridge");
        (void)NSClassFromString(@"BATBridge");
        (void)NSClassFromString(@"DSKBridge");
        shdw_detector_framework_load_ns=shdw_detector_now_ns()-start;
            });
}
void SHDWRunAllDetectors(void){
    if(![NSThread isMainThread]){ dispatch_sync(dispatch_get_main_queue(), ^{ SHDWRunAllDetectors(); }); return; }
    shdw_dlopen_frameworks();
    for(NSString *iid in SHDWAllDetectorIDs()) SHDWRunDetectorWithID(iid);
}
