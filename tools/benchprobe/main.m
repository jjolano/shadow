// benchprobe — on-device per-call microbenchmark battery for Shadow's hooks.
//
// Times ONE representative call per hooked API group in a tight loop and
// emits CSV rows (group,path_class,arm,iters,median_ns,p95_ns,min_ns,max_ns).
// Mirrors hookprobe's canonical probed groups and their pref gates; a group
// whose hook pref is off is reported as a SKIP row, exactly like hookprobe.
// Detector SDK groups (IOSSecuritySuite/FreeRASP/...) and AntiDebug are NOT
// benched here — they only run when a detection library probes, which the
// end-to-end ShadowHarness battery (arm C) measures instead.
//
// Usage (root):
//   benchprobe [--group <name>] [--iters N] [--no-shadow]
//   --group      bench one group only (default: all)
//   --iters      loop count per row (default 10000)
//   --no-shadow  skip dlopen(ShadowCore) — the stock arm
// Exit: 0 = ran, 2 = hooks not active (prefs gate / ctor bail).

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <sandbox.h>
#import <bootstrap.h>
#import <sys/stat.h>
#import <sys/fcntl.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <errno.h>
#import <dlfcn.h>

// The 16.5 SDK stubs out mach_vm.h ("unsupported") — declare the prototype
// manually (flavor BY VALUE; a pointer-form prototype fails with
// KERN_INVALID_ARGUMENT, the bug hookprobe documents).
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);

static NSString* const kShadowCoreBin   = @"/var/jb/usr/lib/ShadowCore.dylib";
static NSString* const kShadowPrefsPlist = @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist";
static NSString* const kRestrictedDir   = @"/var/jb";
static NSString* const kFastAllowedDir  = @"/var/mobile/Documents";   // hits shdw_is_fast_allowed_cpath
static NSString* const kAllowedPath     = @"/usr/lib/libSystem.B.dylib"; // full-decision allowed
static NSString* const kShadowRuleset   = @"/var/jb/Library/Shadow/Rulesets/StandardRules.plist";
static NSString* const kShadowFwk       = @"/var/jb/Library/Frameworks/Shadow.framework";
static NSString* const kShadowService   = @"me.jjolano.shadow.service";
static NSString* const kControlService  = @"com.apple.system.notification_center";

static NSDictionary* gPrefs = nil;
static NSDictionary* gEffectivePrefs = nil;
static const char* gArm = "injected";
static uint64_t gIters = 10000;

// ---------------------------------------------------------------------------
// Effective-prefs model — copied from hookprobe (same resolution ShadowCore's
// ctor uses for a nil bundle ID): shipped defaults overlaid with stored
// suite values only when Global_Enabled.
// ---------------------------------------------------------------------------

static NSSet* shdw_defaultOffKeys(void) {
    static NSSet* set = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        set = [NSSet setWithArray:@[
            @"Hook_Foundation", @"Hook_Memory", @"Hook_Syscall", @"Hook_Sandbox",
            @"Hook_MachBootstrap", @"Hook_IOKit", @"Hook_AntiDebugging",
            @"Hook_DynamicLibrariesExtra"
        ]];
    });

    return set;
}

static NSDictionary* shdw_defaultSettings(void) {
    static NSDictionary* dict = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        NSMutableDictionary* d = [NSMutableDictionary dictionaryWithDictionary:@{
            @"Hook_Filesystem" : @YES,
            @"Hook_URLScheme"  : @YES,
            @"Hook_EnvVars"    : @YES,
            @"Hook_DeviceCheck": @YES,
            @"Hook_LowLevelC"  : @YES,
            @"Hook_HideApps"   : @YES,
            @"MemoryLevelHiding" : @YES
        }];

        for(NSString* key in shdw_defaultOffKeys()) {
            d[key] = @NO;
        }

        dict = [d copy];
    });

    return dict;
}

static BOOL prefsEnabled(NSString* key) {
    if(gEffectivePrefs) {
        id value = [gEffectivePrefs objectForKey:key];

        if(value) {
            return [value boolValue];
        }
    }

    id value = [gPrefs objectForKey:key];

    if(value) {
        return [value boolValue];
    }

    return ![shdw_defaultOffKeys() containsObject:key];
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

static uint64_t nowNs(void) {
    static mach_timebase_info_data_t tb;

    if(tb.denom == 0) {
        mach_timebase_info(&tb);
    }

    uint64_t t = mach_absolute_time();
    return (t * tb.numer) / tb.denom;
}

static int cmpU64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static void emitRow(const char* group, const char* pclass, uint64_t* samples) {
    qsort(samples, gIters, sizeof(uint64_t), cmpU64);
    printf("%s,%s,%s,%llu,%llu,%llu,%llu,%llu\n",
           group, pclass, gArm, (unsigned long long)gIters,
           (unsigned long long)samples[gIters / 2],
           (unsigned long long)samples[(gIters * 95) / 100],
           (unsigned long long)samples[0],
           (unsigned long long)samples[gIters - 1]);
}

static void run(const char* group, const char* pclass, void (*call)(void)) {
    uint64_t* samples = malloc(gIters * sizeof(uint64_t));

    if(!samples) {
        fprintf(stderr, "benchprobe: out of memory\n");
        exit(3);
    }

    for(uint64_t i = 0; i < gIters; i++) {
        uint64_t t0 = nowNs();
        call();
        samples[i] = nowNs() - t0;
    }

    emitRow(group, pclass, samples);
    free(samples);
}

// ---------------------------------------------------------------------------
// Per-group representative calls (mirrors hookprobe's probe functions).
// Each group: optional fast/allowed/restricted path-class calls.
// ---------------------------------------------------------------------------

static void cStatFast(void)     { struct stat st; stat([kFastAllowedDir fileSystemRepresentation], &st); }
static void cStatAllowed(void)  { struct stat st; stat([kAllowedPath fileSystemRepresentation], &st); }
static void cStatRestricted(void){ struct stat st; stat([kRestrictedDir fileSystemRepresentation], &st); }

static void cOpenFast(void)     { int fd = open([kFastAllowedDir fileSystemRepresentation], O_RDONLY); if(fd >= 0) close(fd); }
static void cOpenAllowed(void)  { int fd = open([kAllowedPath fileSystemRepresentation], O_RDONLY); if(fd >= 0) close(fd); }
static void cOpenRestricted(void){ int fd = open([kRestrictedDir fileSystemRepresentation], O_RDONLY); if(fd >= 0) close(fd); }

static void cFmFast(void)       { [[NSFileManager defaultManager] fileExistsAtPath:kFastAllowedDir]; }
static void cFmAllowed(void)    { [[NSFileManager defaultManager] fileExistsAtPath:kAllowedPath]; }
static void cFmRestricted(void) { [[NSFileManager defaultManager] fileExistsAtPath:kRestrictedDir]; }

static void cUrlFast(void)      { [[NSURL fileURLWithPath:kFastAllowedDir] checkResourceIsReachableAndReturnError:nil]; }
static void cUrlAllowed(void)   { [[NSURL fileURLWithPath:kAllowedPath] checkResourceIsReachableAndReturnError:nil]; }
static void cUrlRestricted(void){ [[NSURL fileURLWithPath:kRestrictedDir] checkResourceIsReachableAndReturnError:nil]; }

static void cStringAllowed(void)   { [NSString stringWithContentsOfFile:kShadowPrefsPlist encoding:NSUTF8StringEncoding error:nil]; }
static void cStringRestricted(void){ [NSString stringWithContentsOfFile:kShadowRuleset encoding:NSUTF8StringEncoding error:nil]; }

static void cDataAllowed(void)     { [NSData dataWithContentsOfFile:kShadowPrefsPlist]; }
static void cDataRestricted(void)  { [NSData dataWithContentsOfFile:kShadowCoreBin]; }

static void cDictAllowed(void)     { [NSDictionary dictionaryWithContentsOfFile:kShadowPrefsPlist]; }
static void cDictRestricted(void)  { [NSDictionary dictionaryWithContentsOfFile:kShadowRuleset]; }

static void cFileHandleAllowed(void)    { [NSFileHandle fileHandleForReadingAtPath:kShadowPrefsPlist]; }
static void cFileHandleRestricted(void) { [NSFileHandle fileHandleForReadingAtPath:kShadowCoreBin]; }

static void cBundleAllowed(void)    { [NSBundle bundleWithPath:kFastAllowedDir]; }
static void cBundleRestricted(void) { [NSBundle bundleWithPath:kShadowFwk]; }

static void cSandboxFast(void)      { sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH, [kFastAllowedDir fileSystemRepresentation]); }
static void cSandboxAllowed(void)   { sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH, [kAllowedPath fileSystemRepresentation]); }
static void cSandboxRestricted(void){ sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH, [kRestrictedDir fileSystemRepresentation]); }

static void cObjcAllowed(void)    { NSClassFromString(@"NSString"); }
static void cObjcRestricted(void) { NSClassFromString(@"Shadow"); }

static void cThread(void) { [NSThread callStackSymbols]; }

static void cProcessInfo(void) { [[NSProcessInfo processInfo] environment]; }

static void cUserDefaults(void) { [[NSUserDefaults standardUserDefaults] stringForKey:@"benchprobe-probe-key"]; }

extern int csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
#define CS_OPS_CDHASH 5
static void cCsops(void) { uint8_t buf[20]; csops(getpid(), CS_OPS_CDHASH, buf, sizeof(buf)); }

static void cMachAllowed(void) {
    mach_port_t p;
    bootstrap_look_up(bootstrap_port, [kControlService UTF8String], &p);
}

static void cMachRestricted(void) {
    mach_port_t p;
    bootstrap_look_up(bootstrap_port, [kShadowService UTF8String], &p);
}

static void cVmRegion(void) {
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objName = MACH_PORT_NULL;
    mach_vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                   (vm_region_info_t)&info, &infoCount, &objName);

    if(objName != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), objName);
    }
}

static void cDeviceCheck(void) {
    Class c = objc_getClass("DCDevice");

    if(c && [c respondsToSelector:@selector(currentDevice)]) {
        id device = ((id(*)(id, SEL))objc_msgSend)(c, sel_registerName("currentDevice"));

        if(device && [device respondsToSelector:@selector(isSupported)]) {
            ((BOOL(*)(id, SEL))objc_msgSend)(device, sel_registerName("isSupported"));
        }
    }
}

static void cUIImage(void) {
    Class c = objc_getClass("UIImage");

    if(c) {
        ((id(*)(id, SEL, NSString*))objc_msgSend)(c, sel_registerName("imageNamed:"), @"benchprobe-nonexistent-image");
    }
}

// ---------------------------------------------------------------------------
// Group table
// ---------------------------------------------------------------------------

typedef struct {
    const char* name;
    const char* pref;   // NULL = ungated (always installed)
    void (*fast)(void);
    void (*allowed)(void);
    void (*restricted)(void);
} bench_group;

static const bench_group kGroups[] = {
    { "libc.stat",        "Hook_Filesystem",     cStatFast,       cStatAllowed,       cStatRestricted },
    { "libc.open",        "Hook_LowLevelC",      cOpenFast,       cOpenAllowed,       cOpenRestricted },
    { "nsfilemanager",    "Hook_Foundation",     cFmFast,         cFmAllowed,         cFmRestricted },
    { "nsurl",            "Hook_Foundation",     cUrlFast,        cUrlAllowed,        cUrlRestricted },
    { "nsbundle",         "Hook_Foundation",     NULL,            cBundleAllowed,     cBundleRestricted },
    { "nsstring",         "Hook_Foundation",     NULL,            cStringAllowed,     cStringRestricted },
    { "nsdata",           "Hook_Foundation",     NULL,            cDataAllowed,       cDataRestricted },
    { "nsdictionary",     "Hook_Foundation",     NULL,            cDictAllowed,       cDictRestricted },
    { "nsfilehandle",     "Hook_Foundation",     NULL,            cFileHandleAllowed, cFileHandleRestricted },
    { "nsthread",         "Hook_Foundation",     NULL,            cThread,            NULL },
    { "sandbox",          "Hook_Sandbox",        cSandboxFast,    cSandboxAllowed,    cSandboxRestricted },
    { "syscall.csops",    "Hook_Syscall",        NULL,            cCsops,             NULL },
    { "mach.bootstrap",   "Hook_MachBootstrap",  NULL,            cMachAllowed,       cMachRestricted },
    { "objc.classlookup", NULL,                  NULL,            cObjcAllowed,       cObjcRestricted },
    { "mem.vmregion",     "Hook_Memory",         NULL,            cVmRegion,          NULL },
    { "nsprocessinfo",    "Hook_EnvVars",        NULL,            cProcessInfo,       NULL },
    { "nsuserdefaults",   NULL,                  NULL,            cUserDefaults,      NULL },
    { "devicecheck",      "Hook_DeviceCheck",    NULL,            cDeviceCheck,       NULL },
    { "uikit.imagenamed", "Hook_Foundation",     NULL,            cUIImage,           NULL },
};

static const char* optionValue(int argc, char* argv[], const char* option) {
    for(int i = 1; i + 1 < argc; i++) {
        if(strcmp(argv[i], option) == 0) {
            return argv[i + 1];
        }
    }

    return NULL;
}

static void runGroup(const bench_group* g) {
    if(g->pref && !prefsEnabled([NSString stringWithUTF8String:g->pref])) {
        printf("%s,SKIP,%s,0,0,0,0,0\n", g->name, gArm);
        return;
    }

    if(g->fast) {
        run(g->name, "fast-allowed", g->fast);
    }

    if(g->allowed) {
        run(g->name, "allowed", g->allowed);
    }

    if(g->restricted) {
        run(g->name, "restricted", g->restricted);
    }
}

static BOOL probeCanary(void) {
    struct stat st;
    return stat([kRestrictedDir fileSystemRepresentation], &st) != 0 && errno == ENOENT;
}

int main(int argc, char* argv[]) {
    @autoreleasepool {
        const char* groupName = optionValue(argc, argv, "--group");
        const char* itersStr = optionValue(argc, argv, "--iters");
        const char* noShadow = optionValue(argc, argv, "--no-shadow");

        if(itersStr) {
            gIters = strtoull(itersStr, NULL, 10);

            if(gIters < 10) {
                gIters = 10;
            }
        }

        printf("arm=%s\n", noShadow ? "stock" : "injected");
        gArm = noShadow ? "stock" : "injected";

        gPrefs = [NSDictionary dictionaryWithContentsOfFile:kShadowPrefsPlist];

        NSUserDefaults* ud = [[NSUserDefaults alloc] initWithSuiteName:kShadowPrefsPlist];
        [ud registerDefaults:shdw_defaultSettings()];
        NSMutableDictionary* eff = [shdw_defaultSettings() mutableCopy];

        if([ud boolForKey:@"Global_Enabled"]) {
            eff[@"App_Enabled"] = @YES;

            for(NSString* key in shdw_defaultSettings()) {
                id value = [ud objectForKey:key];

                if(value) {
                    eff[key] = value;
                }
            }
        }

        gEffectivePrefs = [eff copy];

        // Groups that need their framework loaded BEFORE ShadowCore's ctor
        // (absent classes are skipped silently at ctor time, never retried).
        if(prefsEnabled(@"Hook_DeviceCheck")) {
            dlopen("/System/Library/Frameworks/DeviceCheck.framework/DeviceCheck", RTLD_NOW);
        }

        if(prefsEnabled(@"Hook_Foundation")) {
            dlopen("/System/Library/Frameworks/UIKit.framework/UIKit", RTLD_NOW);
        }

        setenv("DYLD_INSERT_LIBRARIES", kShadowCoreBin.UTF8String, 1);

        if(!noShadow) {
            void* handle = dlopen(kShadowCoreBin.UTF8String, RTLD_NOW | RTLD_LOCAL);

            if(!handle) {
                handle = dlopen("/usr/lib/ShadowCore.dylib", RTLD_NOW | RTLD_LOCAL);
            }

            if(!handle) {
                fprintf(stderr, "benchprobe: FATAL: cannot dlopen ShadowCore.dylib (%s)\n", dlerror());
                return 2;
            }

            usleep(500 * 1000);

            if(!probeCanary()) {
                fprintf(stderr, "benchprobe: hooks not active: restricted root is visible. Check Shadow is enabled for this bundle (prefs gate).\n");
                return 2;
            }
        }

        if(groupName) {
            for(size_t i = 0; i < sizeof(kGroups) / sizeof(kGroups[0]); i++) {
                if(strcmp(kGroups[i].name, groupName) == 0) {
                    runGroup(&kGroups[i]);
                    return 0;
                }
            }

            fprintf(stderr, "benchprobe: unknown group: %s\n", groupName);
            return 64;
        }

        for(size_t i = 0; i < sizeof(kGroups) / sizeof(kGroups[0]); i++) {
            runGroup(&kGroups[i]);
        }

        return 0;
    }
}