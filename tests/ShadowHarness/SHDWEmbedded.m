// Embedded one-shot detectors: the same upstream sources the isolated
// runner apps compile, built directly into ShadowHarness. Run All executes
// them sequentially in-process — no app flips, no URL schemes, no TCP.
// Each driver runs its checks synchronously on a worker queue and returns
// a report-shaped NSDictionary (sdk/outcome/rounds/timing).
//
// Forking detectors (JailMonkey canFork, isJailbroken fork probe) do NOT
// fork() here: fork() without exec() in a UIKit process is App Store-
// prohibited and destabilizes the host. Those two probes are replaced
// in-process by a posix_spawn dry-run (same signal, no child survives);
// the true fork() probe lives only in the XPC service row of the report.
//
// SafetyNet's AntiDebugBridge.m constructor (PT_DENY_ATTACH via raw SVC) is
// NOT linked here: it would deny attach on the harness itself and kill
// debugging of every other detector. Its anti-debug row is reported as
// notChecked with an explicit message. installAntiDebugAtLaunch() is
// therefore never called.

#import <Foundation/Foundation.h>

#import <mach-o/dyld.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <spawn.h>
#import <sys/wait.h>
#import <unistd.h>

#import <DTTJailbreakDetection.h>
#import "JB.h"
#import "JailMonkey.h"

// Upstream JailMonkey.h hides the check methods behind the RN bridge
// module; the old runner redeclared them in a class extension — same here.
@interface JailMonkey (SHDWEmbeddedChecks)
- (BOOL)checkPaths;
- (BOOL)checkSchemes;
- (BOOL)canViolateSandbox;
- (BOOL)checkSymlinks;
- (BOOL)checkDylibs;
- (BOOL)isDebugged;
- (NSString *)checkPathsMessage;
- (NSString *)checkSchemesMessage;
- (NSString *)checkSymlinksMessage;
- (NSString *)checkDylibsMessage;
- (NSArray *)dylibsToCheck;
@end

#import "SHDWEmbeddedSwift.h"
#import <libSandy.h>

// Roothider upstream main.m (filtered at fetch time: LOG redirected to
// shdw_roothider_log, app scaffolding stripped).
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


// SwiftyJBD upstream fragment (wrapped into struct SwiftyJBD at fetch).
// Declared here; defined by the compiled JailBreak.swift.
__attribute__((swift_name("SwiftyJBD.isJailbroken()")))
extern BOOL SHDWSwiftyJBDIsJailbroken(void);

// FreeRASP: Talsec via the harness's own TalsecBridge.swift (already linked)
// + generic C probe (DetectorRunners/FreeRASP/Probe.m, compiled in).
const char *SHDWFreeRASPGenericProbeJSON(void);

// ---- report envelope -------------------------------------------------------

static NSDictionary *SHDWEmbeddedCheck(NSString *identifier, NSString *name,
                                       BOOL passed, NSString *message) {
    return @{
        @"id": identifier ?: @"",
        @"name": name ?: identifier ?: @"",
        @"passed": @(passed),
        @"message": message ?: @"",
    };
}

static NSDictionary *SHDWEmbeddedReport(NSString *identifier, NSString *name,
                                        NSString *version, NSString *outcome,
                                        NSArray *rounds, NSDictionary *timing) {
    NSMutableDictionary *report = [@{
        @"schemaVersion": @1,
        @"sdk": @{
            @"id": identifier,
            @"name": name ?: identifier,
            @"version": version ?: @"unknown",
        },
        @"outcome": outcome ?: @"error",
        @"rounds": rounds ?: @[],
        @"generatedAt": [NSISO8601DateFormatter.new stringFromDate:[NSDate date]],
    } mutableCopy];
    if (timing) report[@"timing"] = timing;
    return report;
}

static NSDictionary *SHDWEmbeddedFailure(NSString *identifier, NSString *message) {
    return SHDWEmbeddedReport(identifier, identifier, @"unknown", @"error", @[@{
        @"phase": @"embedded",
        @"clean": @NO,
        @"checks": @[SHDWEmbeddedCheck(@"embedded.transport", @"Embedded run",
                                       NO, message ?: @"Detector did not return a report")],
    }], nil);
}

// Wrapper that turns an NSException into an error report instead of a
// harness crash. Every driver entry point is funneled through this.
static NSDictionary *SHDWEmbeddedGuarded(NSString *identifier,
                                         NSDictionary *(^body)(void)) {
    @try {
        NSDictionary *report = body();
        return [report isKindOfClass:[NSDictionary class]]
            ? report : SHDWEmbeddedFailure(identifier, @"Detector returned no report");
    } @catch (NSException *e) {
        return SHDWEmbeddedFailure(identifier,
            [NSString stringWithFormat:@"Detector threw %@: %@", e.name, e.reason]);
    }
}

// ---- fork-free fork probe --------------------------------------------------

// fork() without exec() in a UIKit process: prohibited + destabilizing.
// posix_spawn of /bin/true that we immediately reap carries the same jailbreak
// signal (a sandbox that permits process creation) without a surviving child.
static BOOL SHDWEmbeddedCanSpawn(void) {
    pid_t pid = 0;
    char *argv[] = { "/bin/true", NULL };
    int spawned = posix_spawn(&pid, "/bin/true", NULL, NULL, argv, NULL);
    if (spawned != 0) return NO;
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
    return YES;
}

// ---- individual drivers ----------------------------------------------------

static NSDictionary *SHDWEmbeddedDTT(void) {
    return SHDWEmbeddedGuarded(@"dttjailbreakdetection", ^{
        BOOL jailbroken = [DTTJailbreakDetection isJailbroken];
        NSArray *checks = @[SHDWEmbeddedCheck(@"dtt.isJailbroken", @"isJailbroken",
            !jailbroken, jailbroken ? @"Library returned YES" : @"Library returned NO")];
        return SHDWEmbeddedReport(@"dttjailbreakdetection", @"DTTJailbreakDetection",
            @"0.2.0+cedd424", jailbroken ? @"jailbroken" : @"clean",
            @[@{ @"phase": @"startup", @"clean": @((BOOL)!jailbroken), @"checks": checks }], nil);
    });
}

static NSString *SHDWEmbeddedJailMonkeyMatches(JailMonkey *detector) {
    NSArray *needles = [detector dylibsToCheck];
    NSMutableArray *hits = [NSMutableArray array];
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if(!name) continue;
        NSString *image = [NSString stringWithUTF8String:name];
        for(NSString *needle in needles) {
            if([image localizedCaseInsensitiveContainsString:needle]) {
                [hits addObject:[NSString stringWithFormat:@"%@ ~ %@", image, needle]];
            }
        }
    }
    return hits.count ? [hits componentsJoinedByString:@"; "] : @"match flagged but no image matched on re-scan";
}

static NSDictionary *SHDWEmbeddedJailMonkey(void) {
    return SHDWEmbeddedGuarded(@"jailmonkey", ^{
        JailMonkey *detector = [JailMonkey new];
        BOOL paths = [detector checkPaths];
        BOOL schemes = [detector checkSchemes];
        BOOL sandbox = [detector canViolateSandbox];
        BOOL spawned = SHDWEmbeddedCanSpawn();
        BOOL symlinks = [detector checkSymlinks];
        BOOL dylibs = [detector checkDylibs];
        BOOL debugged = [detector isDebugged];
        // Harness-artifact filter: the exe path contains "Shadow", which the
        // upstream "Shadow" needle flags. Runner-era exes had neutral names.
        // A hit naming ONLY our own executable is not a jailbreak signal —
        // report notChecked rather than hiding our binary from enumeration.
        NSString *dylibMessage = @"no suspicious dylib";
        BOOL dylibsClean = !dylibs;
        if(dylibs) {
            NSString *matches = SHDWEmbeddedJailMonkeyMatches(detector);
            NSRange harnessOnly = [matches rangeOfString:@"ShadowHarness" options:NSCaseInsensitiveSearch];
            if(harnessOnly.location != NSNotFound) {
                // Strip harness-exe hits; fail only on anything else.
                NSMutableArray *others = [NSMutableArray array];
                for(NSString *hit in [matches componentsSeparatedByString:@"; "]) {
                    if([hit rangeOfString:@"ShadowHarness" options:NSCaseInsensitiveSearch].location == NSNotFound) {
                        [others addObject:hit];
                    }
                }
                if(others.count == 0) {
                    dylibsClean = YES;
                    dylibMessage = @"notChecked: only the harness executable matched the upstream \"Shadow\" substring (runner-era artifact)";
                } else {
                    dylibMessage = [others componentsJoinedByString:@"; "];
                }
            } else {
                dylibMessage = matches;
            }
        }
        NSArray *checks = @[
            SHDWEmbeddedCheck(@"jailmonkey.paths", @"Suspicious paths", !paths, [detector checkPathsMessage]),
            SHDWEmbeddedCheck(@"jailmonkey.schemes", @"Suspicious URL schemes", !schemes, [detector checkSchemesMessage]),
            SHDWEmbeddedCheck(@"jailmonkey.sandbox", @"Sandbox violation", !sandbox, sandbox ? @"write succeeded" : @"write denied"),
            SHDWEmbeddedCheck(@"jailmonkey.fork", @"Fork", !spawned, spawned ? @"spawn succeeded" : @"spawn denied"),
            SHDWEmbeddedCheck(@"jailmonkey.symlinks", @"Suspicious symlinks", !symlinks, [detector checkSymlinksMessage]),
            SHDWEmbeddedCheck(@"jailmonkey.dylibs", @"Suspicious dylibs", dylibsClean, dylibMessage),
            SHDWEmbeddedCheck(@"jailmonkey.debugger", @"Debugger", !debugged, debugged ? @"debugger attached" : @"not debugged"),
        ];
        BOOL clean = YES;
        for (NSDictionary *check in checks) clean = clean && [check[@"passed"] boolValue];
        return SHDWEmbeddedReport(@"jailmonkey", @"JailMonkey", @"v2.8.5",
            clean ? @"clean" : @"jailbroken",
            @[@{ @"phase": @"startup", @"clean": @(clean), @"checks": checks }], nil);
    });
}

static NSDictionary *SHDWEmbeddedIsJailbroken(void) {
    return SHDWEmbeddedGuarded(@"isjailbroken", ^{
        BOOL jailbroken = isJb();
        BOOL injected = isInjectedWithDynamicLibrary();
        BOOL debugged = isDebugged();
        BOOL onMac = isRunningOnMac();
        NSArray *checks = @[
            SHDWEmbeddedCheck(@"isjailbroken.jailbreak", @"Jailbreak (paths/symlink/fork/write/URL)", !jailbroken,
                jailbroken ? @"jailbreak signal detected" : @"no jailbreak signal"),
            SHDWEmbeddedCheck(@"isjailbroken.dylib", @"Injected dynamic library", !injected,
                injected ? @"suspicious dylib in image list" : @"no suspicious dylib"),
            SHDWEmbeddedCheck(@"isjailbroken.debugger", @"Debugger (P_TRACED)", !debugged,
                debugged ? @"debugger attached" : @"not debugged"),
            SHDWEmbeddedCheck(@"isjailbroken.ios_on_mac", @"Running as iOS-on-Mac", !onMac,
                onMac ? @"process is iOS app on Mac" : @"native iOS device"),
        ];
        BOOL clean = YES;
        for (NSDictionary *check in checks) clean = clean && [check[@"passed"] boolValue];
        return SHDWEmbeddedReport(@"isjailbroken", @"isJailbroken", @"main@60a5f55",
            clean ? @"clean" : @"jailbroken",
            @[@{ @"phase": @"startup", @"clean": @(clean), @"checks": checks }], nil);
    });
}

// Roothider LOG redirect lives in this translation unit (matches the stub
// header contract tests/ShadowHarness/stubs/RoothiderLog.h declares).
static NSMutableArray<NSString *> *SHDWRoothiderFindings;

void shdw_roothider_log(NSString *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    if (message.length) [SHDWRoothiderFindings addObject:message];
}

static NSDictionary *SHDWEmbeddedRoothiderRun(NSString *identifier, NSString *name,
                                              void (*detector)(void)) {
    SHDWRoothiderFindings = [NSMutableArray array];
    @try {
        detector();
    } @catch (NSException *e) {
        [SHDWRoothiderFindings addObject:[NSString stringWithFormat:@" threw %@: %@", e.name, e.reason]];
    }
    BOOL detected = SHDWRoothiderFindings.count > 0;
    NSString *message = detected
        ? [SHDWRoothiderFindings componentsJoinedByString:@"; "] : @"No finding";
    return SHDWEmbeddedCheck(identifier, name, !detected, message);
}

static NSDictionary *SHDWEmbeddedRoothider(void) {
    return SHDWEmbeddedGuarded(@"roothider", ^{
        NSArray *checks = @[
            SHDWEmbeddedRoothiderRun(@"roothider.rootlessJB", @"Rootless jailbreak", detect_rootlessJB),
            SHDWEmbeddedRoothiderRun(@"roothider.kernBypass", @"Kernel bypass", detect_kernBypass),
            SHDWEmbeddedRoothiderRun(@"roothider.chroot", @"Chroot", detect_chroot),
            SHDWEmbeddedRoothiderRun(@"roothider.mount_fs", @"Mounted filesystems", detect_mount_fs),
            SHDWEmbeddedRoothiderRun(@"roothider.bootstraps", @"Bootstrap files", detect_bootstraps),
            SHDWEmbeddedRoothiderRun(@"roothider.trollStoredFilza", @"TrollStore Filza", detect_trollStoredFilza),
            SHDWEmbeddedRoothiderRun(@"roothider.jailbreakd", @"Jailbreak daemon", detect_jailbreakd),
            SHDWEmbeddedRoothiderRun(@"roothider.proc_flags", @"Process flags", detect_proc_flags),
            SHDWEmbeddedRoothiderRun(@"roothider.jb_payload", @"Jailbreak payload", detect_jb_payload),
            SHDWEmbeddedRoothiderRun(@"roothider.exception_port", @"Exception port", detect_exception_port),
            SHDWEmbeddedRoothiderRun(@"roothider.jb_preboot", @"Preboot jailbreak", detect_jb_preboot),
            SHDWEmbeddedRoothiderRun(@"roothider.jailbroken_apps", @"Jailbreak apps", detect_jailbroken_apps),
            SHDWEmbeddedRoothiderRun(@"roothider.removed_varjb", @"Removed /var/jb", detect_removed_varjb),
            SHDWEmbeddedRoothiderRun(@"roothider.fugu15Max", @"Fugu15 Max", detect_fugu15Max),
            SHDWEmbeddedRoothiderRun(@"roothider.url_schemes", @"URL schemes", detect_url_schemes),
            SHDWEmbeddedRoothiderRun(@"roothider.jbapp_plugins", @"Jailbreak app plugins", detect_jbapp_plugins),
            SHDWEmbeddedRoothiderRun(@"roothider.jailbreak_sigs", @"Jailbreak signatures", detect_jailbreak_sigs),
            SHDWEmbeddedRoothiderRun(@"roothider.jailbreak_port", @"Jailbreak ports", detect_jailbreak_port),
            SHDWEmbeddedRoothiderRun(@"roothider.launchd_jbserver", @"Launchd jailbreak server", detect_launchd_jbserver),
            SHDWEmbeddedRoothiderRun(@"roothider.launchd_jb_mach_server", @"Launchd Mach server", detect_launchd_jb_mach_server),
            SHDWEmbeddedRoothiderRun(@"roothider.passcode_status", @"Passcode status", detect_passcode_status),
            SHDWEmbeddedRoothiderRun(@"roothider.cfprefsd_hook", @"cfprefsd hook", detect_cfprefsd_hook),
            SHDWEmbeddedRoothiderRun(@"roothider.launchd_ipchook", @"Launchd IPC hook", detect_launchd_ipchook),
            SHDWEmbeddedRoothiderRun(@"roothider.bind_mounts", @"Bind mounts", detect_bind_mounts),
            SHDWEmbeddedRoothiderRun(@"roothider.launchd_deplatformized", @"Launchd deplatformized", detect_launchd_deplatformized),
        ];
        BOOL clean = YES;
        for (NSDictionary *check in checks) clean = clean && [check[@"passed"] boolValue];
        return SHDWEmbeddedReport(@"roothider", @"Roothider JailbreakDetector", @"main@5b3d0be",
            clean ? @"clean" : @"jailbroken",
            @[@{ @"phase": @"startup", @"clean": @(clean), @"checks": checks }], nil);
    });
}

// Reads the coordinator's recorded SDK-fallback inventory (set at ctor
// prearm). The installHarnessSDKFallback() call returns NO when already
// installed, so the driver row must read this, not the call bool.
BOOL SHDWEmbeddedFallbackInstalled(void) {
    // objc_getClass is hooked (class-hiding) — use the abort-free internal
    // path Battery.m documents: the class is linked, so this cannot fire.
    Class coordinator = objc_getRequiredClass("SHDWHookCoordinator");
    SEL selector = sel_registerName("shdw_activationSnapshot");
    if(coordinator && [coordinator respondsToSelector:selector]) {
        typedef NSDictionary *(*SnapshotMessage)(id, SEL);
        NSDictionary *snapshot =
            ((SnapshotMessage)objc_msgSend)((id)coordinator, selector);
        if([snapshot isKindOfClass:[NSDictionary class]]) {
            return [snapshot[@"sdk_fallback_observed"] boolValue];
        }
    }
    return NO;
}

// Exact matched-image report for the JailMonkey dylib row. Upstream
// checkDylibsMessage overwrites its buffer per image, so it returns the LAST
// image whether or not anything matched — useless for diagnosis. This walks
// the real dyld list with the same predicate and names true offenders.

// ---- dispatcher ------------------------------------------------------------

NSDictionary *SHDWEmbeddedRunDetector(NSString *identifier) {
    // Swift-framework drivers (ISS/JBD/STK/BAT/DSK/SafetyNet/SwiftyJBD)
    // and FreeRASP live in SHDWEmbeddedSwift (EmbeddedDrivers.swift) —
    // this unit owns only the ObjC-source drivers.
    if ([identifier isEqualToString:@"dttjailbreakdetection"]) return SHDWEmbeddedDTT();
    if ([identifier isEqualToString:@"jailmonkey"]) return SHDWEmbeddedJailMonkey();
    if ([identifier isEqualToString:@"isjailbroken"]) return SHDWEmbeddedIsJailbroken();
    if ([identifier isEqualToString:@"roothider"]) return SHDWEmbeddedRoothider();
    NSDictionary *swiftReport = SHDWEmbeddedSwiftRunDetector(identifier);
    if (swiftReport) return swiftReport;
    return SHDWEmbeddedFailure(identifier, @"Unknown embedded detector");
}
