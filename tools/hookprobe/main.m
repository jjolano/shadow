// hookprobe — on-device runtime battery for Shadow's hook layer.
//
// Unlike the host harness (which compiles the decision engine directly) and
// ShadowTest (which only proves hooks INSTALL), this tool dlopens ShadowCore
// in-process and then CALLS each hooked API group with a restricted path and
// a control path, asserting the filtered behavior.
//
// Run as root on the device:
//   sudo /var/jb/usr/bin/hookprobe
// Exit code: 0 = all probes passed, 1 = probe failure(s), 2 = hooks not
// active (prefs gate / ctor bail — check Shadow is enabled for this bundle).
//
// Prefs-aware: groups the effective global prefs disable are reported SKIP
// (the hook is legitimately not installed), not FAIL.
//
// SKIP groups: UIApplication (no singleton in CLI context), iokit
// (empty-iterator hide == stock no-match for an absent restricted service
// class), LSApplicationWorkspace (no restricted app installed — vacuous
// filter), NSArray (no restricted fixture parses natively as an array —
// dict-rooted ruleset returns nil natively), and groups the effective
// global prefs disable (shipped defaults: Syscall/Sandbox/MachBootstrap/
// Memory/Foundation/IOKit/AntiDebugging ship OFF). Probed groups: libc, dyld,
// objc, mem, syscall (csops), DeviceCheck,
// UIImage, NSFileManager/NSURL/NSBundle/NSString/NSData/NSDictionary/
// NSFileHandle, NSThread, NSFileVersion/NSFileWrapper, NSProcessInfo, mach,
// sandbox, NSUserDefaults.
//
// Load order (Run A, proven on-device): DeviceCheck.framework and
// UIKit.framework both preload BEFORE dlopen(ShadowCore). The ctor's
// descriptor install needs DCDevice present at ctor time (absent classes are
// skipped silently, never retried), and the ctor's UIKit-load watcher replay
// (dylib.x:1042-1050) installs the UIImage group for already-loaded UIKit.
// libc probes split by install group: stat/access under Hook_Filesystem
// (LIBC table group), open/opendir under Hook_LowLevelC (LOW table group,
// libc.x:2103-2106) — gated separately so neither false-FAILs the other.

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <bootstrap.h>
#import <sandbox.h>
#import <dlfcn.h>
#import <ctype.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <dirent.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>

#import "identity_fixture.h"

// The 16.5 SDK stubs out mach_vm.h ("unsupported") — declare the prototype
// manually. The flavor is BY VALUE (a pointer-form prototype passes a
// pointer where the kernel expects the int flavor and the call fails with
// KERN_INVALID_ARGUMENT; the production mem.x hook had this bug until
// corrected there).
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);

// The 16.5 SDK ships no sys/codesign.h — declare the csops prototype and the
// CDHASH op manually (CS_OPS_CDHASH == 5 per vendor/apple/codesign.h; 7 is
// CS_OPS_ENTITLEMENTS_BLOB).
extern int csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);
#define CS_OPS_CDHASH 5

// The DeviceCheck/UIImage probes dispatch via runtime selectors (the tool
// links only Foundation; a static class ref would need the framework at
// link time). Runtime selectors trip -Warc-performSelector-leaks, an error
// under -Werror — suppressed: every performSelector here targets a class or
// instance we keep alive for the whole run (never a selector the runtime
// could treat as returning a new object).
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

// ---------------------------------------------------------------------------
// Result ledger
// ---------------------------------------------------------------------------

static int gPass = 0;
static int gFail = 0;
static int gSkip = 0;
static NSMutableArray* gProbeRows = nil;

// The host ledger owns the detailed source-level contract for each ID.  This
// table names the on-device witness that proves the corresponding installed
// hook group is live on the frozen candidate.  A witness is deliberately
// concrete (rather than an aggregate score): a changed or skipped probe makes
// every dependent canonical row fail visibly.
typedef struct {
    const char* identifier;
    const char* witnesses[5];
} CanonicalRegression;

static const CanonicalRegression kCanonicalRegressions[] = {
    { "C-01",    { "libc|open(restricted)", "libc|opendir(restricted)" } },
    { "C-02",    { "libc|stat(restricted)" } },
    { "C-03",    { "libc|stat(restricted)" } },
    { "C-04",    { "libc|open(restricted)" } },
    { "C-05",    { "libc|opendir(restricted)" } },
    { "C-06",    { "libc|getenv(DYLD_INSERT_LIBRARIES)", "NSProcessInfo|environment sanitized" } },
    { "C-07",    { "syscall|csops(CDHASH)" } },
    { "C-08",    { "syscall|csops(invalid op) control" } },
    { "C-09",    { "libc|stat(restricted)", "libc|open(restricted)" } },
    { "C-10",    { "syscall|csops(CDHASH)", "syscall|csops(invalid op) control" } },
    { "C-11",    { "mem|vm_region hides ShadowCore" } },
    { "C-12",    { "mach|bootstrap_look_up(restricted service)", "mach|bootstrap_look_up(control service)" } },
    { "C-13",    { "sandbox|sandbox_check(restricted)", "sandbox|sandbox_check(control)" } },
    { "C-14",    { "libc|open(restricted)" } },
    { "C-15",    { "sandbox|sandbox_check(control)" } },
    { "C-16",    { "syscall|csops(CDHASH)" } },
    { "C-17",    { "libc|getenv(DYLD_INSERT_LIBRARIES)", "mach|bootstrap_look_up(restricted service)", "sandbox|sandbox_check(restricted)", "syscall|csops(CDHASH)" } },
    { "CORE-01", { "libc|stat(restricted)", "libc|open(restricted)" } },
    { "CORE-02", { "dyld|dladdr(shadowcore)", "objc|NSClassFromString(Shadow)" } },
    { "CORE-03", { "NSFileManager|attributesOfItemAtPath(restricted)", "NSURL|checkResourceIsReachable(restricted)" } },
    { "CORE-04", { "LSApplicationWorkspace|applicationsAvailableForHandlingURLScheme(restricted)" } },
    { "CORE-05", { "LSApplicationWorkspace|applicationProxyForIdentifier(restricted)", "objc|NSClassFromString(Shadow)" } },
    { "CORE-06", { "objc|NSClassFromString(Shadow)", "objc|objc_getClass(Shadow)" } },
    { "CORE-07", { "NSProcessInfo|environment sanitized", "NSUserDefaults|standard defaults roundtrip" } },
    { "CORE-08", { "libc|stat(restricted)", "libc|opendir(restricted)" } },
    { "CORE-09", { "NSFileManager|fileExistsAtPath(restricted)", "libc|stat(restricted)" } },
    { "DY-01",  { "dyld|dladdr(shadowcore)", "mem|vm_region hides ShadowCore" } },
    { "DY-02",  { "objc|NSClassFromString(Shadow)" } },
    { "DY-03",  { "objc|objc_getClass(Shadow)" } },
    { "DY-04",  { "objc|NSClassFromString(Shadow)", "objc|objc_getClass(Shadow)" } },
    { "DY-05",  { "dyld|dladdr(shadowcore)" } },
    { "DY-06",  { "dyld|dladdr(shadowcore)" } },
    { "DY-07",  { "dyld|dladdr(CFGetTypeID) control" } },
    { "DY-08",  { "dyld|dladdr(shadowcore)", "mem|vm_region hides ShadowCore" } },
    { "DY-09",  { "objc|NSClassFromString(Shadow)" } },
    { "DY-10",  { "NSBundle|bundleWithPath(shadowfwk)", "dyld|dladdr(shadowcore)" } },
    { "DY-11",  { "objc|objc_getClass(Shadow)" } },
    { "DY-12",  { "dyld|dladdr(shadowcore)" } },
    { "FILE-01", { "NSFileManager|attributesOfItemAtPath(restricted)" } },
    { "FILE-02", { "NSFileManager|fileExistsAtPath(restricted)", "NSFileManager|isReadableFileAtPath(restricted)", "NSFileManager|contentsOfDirectoryAtPath(restricted)" } },
    { "FILE-03", { "NSFileManager|contentsOfDirectoryAtPath(restricted)" } },
    { "FILE-04", { "libc|stat(restricted)", "NSFileManager|fileExistsAtPath(restricted)" } },
    { "FILE-05", { "NSURL|checkResourceIsReachable(restricted)", "NSURL|fileReferenceURL(restricted)", "NSURL|filePathURL(restricted)" } },
    { "FILE-06", { "NSURL|checkResourceIsReachable(restricted)" } },
    { "FILE-07", { "NSURL|checkResourceIsReachable(control)" } },
    { "FILE-08", { "NSFileVersion|currentVersionOfItemAtURL(restricted)", "NSFileVersion|currentVersionOfItemAtURL(control)" } },
    { "FILE-09", { "NSFileManager|fileExistsAtPath(restricted)", "NSURL|checkResourceIsReachable(restricted)" } },
    { "FILE-10", { "NSString|stringWithContentsOfFile(ruleset)", "NSData|dataWithContentsOfFile(shadowcore)", "NSDictionary|dictionaryWithContentsOfFile(ruleset)" } },
    { "N-01",   { "NSThread|callStack* filtered" } },
    { "N-02",   { "NSProcessInfo|environment sanitized", "libc|getenv(DYLD_INSERT_LIBRARIES)" } },
    { "N-03",   { "LSApplicationWorkspace|applicationProxyForIdentifier(restricted)" } },
    { "N-04",   { "NSFileVersion|currentVersionOfItemAtURL(restricted)" } },
    { "N-05",   { "DeviceCheck|DCDevice.isSupported baseline", "DeviceCheck|DCDevice.isSupported" } },
    { "N-06",   { "LSApplicationWorkspace|applicationsAvailableForHandlingURLScheme(restricted)" } },
    { "N-07",   { "UIImage|imageNamed(inBundle:) baseline", "UIImage|imageNamed(inBundle:)" } },
    { "N-08",   { "NSBundle|bundleWithPath(shadowfwk)", "NSBundle|mainBundle(control)" } },
    { "N-09",   { "NSString|stringWithContentsOfFile(ruleset)" } },
    { "N-10",   { "NSData|dataWithContentsOfFile(shadowcore)", "NSDictionary|dictionaryWithContentsOfFile(ruleset)" } },
};

static NSDictionary* probeForWitness(const char* witness) {
    NSString* needle = [NSString stringWithUTF8String:witness];

    for(NSDictionary* probe in gProbeRows) {
        NSString* key = [NSString stringWithFormat:@"%@|%@", probe[@"group"], probe[@"name"]];

        if([key isEqualToString:needle]) {
            return probe;
        }
    }

    return nil;
}

static NSArray* canonicalRegressionRows(BOOL* complete) {
    NSMutableArray* rows = [NSMutableArray array];
    NSMutableSet* identifiers = [NSMutableSet set];
    BOOL valid = YES;

    for(NSUInteger i = 0; i < sizeof(kCanonicalRegressions) / sizeof(kCanonicalRegressions[0]); i++) {
        const CanonicalRegression* mapping = &kCanonicalRegressions[i];
        NSString* identifier = @(mapping->identifier);
        NSMutableArray* witnesses = [NSMutableArray array];
        BOOL passed = mapping->identifier[0] != '\0' && ![identifiers containsObject:identifier];

        [identifiers addObject:identifier];

        for(NSUInteger j = 0; j < sizeof(mapping->witnesses) / sizeof(mapping->witnesses[0]); j++) {
            const char* witness = mapping->witnesses[j];

            if(!witness) {
                break;
            }

            NSDictionary* probe = probeForWitness(witness);
            NSString* status = probe[@"status"] ?: @"MISSING";
            [witnesses addObject:@{ @"probe" : @(witness), @"status" : status }];
            passed = passed && [status isEqualToString:@"PASS"];
        }

        valid = valid && witnesses.count > 0;
        [rows addObject:@{ @"id" : identifier, @"status" : passed ? @"PASS" : @"FAIL",
                           @"witnesses" : witnesses }];
    }

    valid = valid && rows.count == 58 && identifiers.count == 58;

    if(complete) {
        *complete = valid;
    }

    return rows;
}

static void recordProbe(NSString* group, NSString* name, NSString* status, NSString* detail) {
    if(gProbeRows) {
        [gProbeRows addObject:@{ @"group" : group, @"name" : name,
                                 @"status" : status, @"detail" : detail }];
    }
}

static void report(NSString* group, NSString* name, BOOL ok, NSString* detail) {
    if(ok) {
        gPass += 1;
        recordProbe(group, name, @"PASS", detail);
        NSLog(@"[hookprobe] PASS %@::%@ %@", group, name, detail);
    } else {
        gFail += 1;
        recordProbe(group, name, @"FAIL", detail);
        NSLog(@"[hookprobe] FAIL %@::%@ %@", group, name, detail);
    }
}

static void skip(NSString* group, NSString* name, NSString* reason) {
    gSkip += 1;
    recordProbe(group, name, @"SKIP", reason);
    NSLog(@"[hookprobe] SKIP %@::%@ (%@)", group, name, reason);
}

// ---------------------------------------------------------------------------
// Probe paths — real, existing, restricted files only. A synthesized
// nonexistent path would pass every probe trivially.
// ---------------------------------------------------------------------------

static NSString* const kRestrictedDir = @"/var/jb";
static NSString* const kShadowCoreBin = @"/var/jb/usr/lib/ShadowCore.dylib";
static NSString* const kShadowRuleset = @"/var/jb/Library/Shadow/Rulesets/StandardRules.plist";
static NSString* const kShadowFwk    = @"/var/jb/Library/Frameworks/Shadow.framework";
static NSString* const kShadowFwkBin = @"/var/jb/Library/Frameworks/Shadow.framework/Shadow";
static NSString* const kControlDir   = @"/var/mobile/Documents";

// Shared preference suite used to resolve the effective hook configuration.
static NSString* const kShadowPrefsPlist = @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist";

// ---------------------------------------------------------------------------
// Hooks-live canary: with the hook layer active, stat() on the restricted
// root must fail with ENOENT. No fallback path (a fallback to a possibly
// nonexistent path yields a false ENOENT with hooks OFF).
// ---------------------------------------------------------------------------

static BOOL probeCanary(void) {
    struct stat st;
    errno = 0;

    return stat([kRestrictedDir fileSystemRepresentation], &st) != 0 && errno == ENOENT;
}

// ---------------------------------------------------------------------------
// Effective global prefs: groups the global settings disable are SKIPped.
// gEffectivePrefs is the battery's replication of ShadowCore's ctor-time
// resolution (ShadowSettings getPreferencesForIdentifier: for a nil bundle
// ID, Settings.m:92-128): shipped defaults (SHDWDefaultHookSettings,
// HookConfiguration.m:55-82) overlaid with the stored suite values when
// Global_Enabled — read pre-dlopen through the NSUserDefaults suite, the
// same cfprefsd mediation the ctor uses (no hooks installed yet, so the
// reads are unhooked). gPrefs is the RAW plist read, kept only as a
// fallback when the suite resolution is unavailable.
// ---------------------------------------------------------------------------

static NSDictionary* gPrefs = nil;
static NSDictionary* gEffectivePrefs = nil;  // resolved pre-dlopen in main()

static NSSet* shdw_defaultOffKeys(void) {
    static NSSet* set = nil;
    static dispatch_once_t onceToken = 0;

    dispatch_once(&onceToken, ^{
        set = [NSSet setWithArray:@[
            @"Hook_Foundation",
            @"Hook_Memory",
            @"Hook_Syscall",
            @"Hook_Sandbox",
            @"Hook_MachBootstrap",
            @"Hook_IOKit",
            @"Hook_AntiDebugging",
            @"Hook_DynamicLibrariesExtra"
        ]];
    });

    return set;
}

// Mirror of SHDWDefaultHookSettings (HookConfiguration.m:55-82) — the single
// source of truth. Built from shdw_defaultOffKeys (→ NO) plus every other
// key the battery queries (→ YES) so the two cannot drift: a key shipping
// ON that this mirror misses would silently untest its group.
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
        // ShadowCore's effective resolution; the dict always contains every
        // defaultSettings key. A missing key is unexpected — fall through to
        // the raw model as a safety net.
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
// libc group (libc.x): stat/access are in the LIBC table group (installs
// under Hook_Filesystem, libc.x:2045/2053); open/opendir are in the LOW
// table group (installs under Hook_LowLevelC, libc.x:2103-2106, dylib.x:882).
// Probed separately so a Filesystem-only install does not false-FAIL
// open/opendir — and vice versa. Tier 1, ctor-installed.
// ---------------------------------------------------------------------------

static void probeLibcFilesystem(void) {
    struct stat st;

    errno = 0;
    BOOL statHidden = stat([kRestrictedDir fileSystemRepresentation], &st) != 0 && errno == ENOENT;
    report(@"libc", @"stat(restricted)", statHidden, [NSString stringWithFormat:@"errno=%d", errno]);

    errno = 0;
    BOOL accessHidden = access([kRestrictedDir fileSystemRepresentation], F_OK) != 0 && errno == ENOENT;
    report(@"libc", @"access(restricted)", accessHidden, [NSString stringWithFormat:@"errno=%d", errno]);

    errno = 0;
    BOOL controlVisible = stat([kControlDir fileSystemRepresentation], &st) == 0;
    report(@"libc", @"stat(control)", controlVisible, [NSString stringWithFormat:@"errno=%d", errno]);
}

static void probeLibcLowLevel(void) {
    errno = 0;
    int fd = open([kRestrictedDir fileSystemRepresentation], O_RDONLY);
    BOOL openHidden = fd < 0 && errno == ENOENT;

    if(fd >= 0) {
        close(fd);
    }

    report(@"libc", @"open(restricted)", openHidden, [NSString stringWithFormat:@"errno=%d", errno]);

    errno = 0;
    DIR* dir = opendir([kRestrictedDir fileSystemRepresentation]);
    BOOL opendirHidden = dir == NULL && errno == ENOENT;

    if(dir) {
        closedir(dir);
    }

    report(@"libc", @"opendir(restricted)", opendirHidden, [NSString stringWithFormat:@"errno=%d", errno]);
}

// ---------------------------------------------------------------------------
// ShadowCore header capture: loader-safe add-image callback. The callback
// stores ONLY raw mach_header pointers (no dladdr, no Foundation, no
// allocation — work inside the callback during dlopen/ctor re-entered the
// hook machinery and broke installation). ShadowCore is identified AFTER
// dlopen by parsing each header's LC_ID_DYLIB basename. main() discards the
// registration-time REPLAY (which fills the slots with already-loaded images
// before ShadowCore loads) so the real notification — fired when dlopen maps
// ShadowCore — lands in the capture array. The real mapped header DOES carry
// LC_ID_DYLIB.
// ---------------------------------------------------------------------------

#define kMaxCapturedImages 64
static const struct mach_header* gCapturedHeaders[kMaxCapturedImages];
static uint32_t gCapturedCount = 0;

static void shadowcore_add_image(const struct mach_header* mh, intptr_t vmaddr_slide) {
    (void) vmaddr_slide;

    if(gCapturedCount < kMaxCapturedImages) {
        gCapturedHeaders[gCapturedCount++] = mh;
    }
}

static BOOL shdw_is_shadowcore_header(const struct mach_header* mh) {
    if(!mh || mh->magic != MH_MAGIC_64) {
        return NO;
    }

    const struct mach_header_64* mh64 = (const void*)mh;
    const struct load_command* lc = (const void *)(mh64 + 1);

    for(uint32_t j = 0; j < mh64->ncmds; j++) {
        if(lc->cmd == LC_ID_DYLIB) {
            const struct dylib_command* dc = (const void*)lc;
            const char* name = (const char*)dc + dc->dylib.name.offset;
            const char* base = strrchr(name, '/');

            if(base && strstr(base, "ShadowCore") != NULL) {
                return YES;
            }
        }

        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }

    return NO;
}

// NOTE: handle may be NULL (dlopen failed) — caller checks. There is NO
// dlopen-handle-as-header fallback: a dyld4 dlopen handle is a Loader*, not
// the image's mach_header, so the handle can never substitute for the
// captured header. A NULL result is a setup failure, reported FAIL.
static const struct mach_header* findShadowCoreHeader(void) {
    for(uint32_t i = 0; i < gCapturedCount; i++) {
        if(shdw_is_shadowcore_header(gCapturedHeaders[i])) {
            return gCapturedHeaders[i];
        }
    }

    return NULL;
}

// ---------------------------------------------------------------------------
// dyld group (dyld.x): dladdr on ShadowCore's mach_header must not resolve
// to ShadowCore (symlookup hides Shadow images). The header was captured
// unhooked before the ctor ran. A NULL header is a SETUP FAILURE (the real
// mapped header carries LC_ID_DYLIB; the capture depends on the callback
// firing for the dlopen) — reported FAIL, not SKIP.
// ---------------------------------------------------------------------------

static void probeDyld(const struct mach_header* shadowCoreHeader) {
    if(!shadowCoreHeader) {
        report(@"dyld", @"dladdr(shadowcore)", NO, @"ShadowCore header not captured (callback replay discard fix ineffective)");
        return;
    }

    Dl_info info;
    memset(&info, 0, sizeof(info));

    if(dladdr(shadowCoreHeader, &info) && info.dli_fname) {
        NSString* fname = [NSString stringWithUTF8String:info.dli_fname];
        BOOL hidden = [fname rangeOfString:@"ShadowCore" options:NSCaseInsensitiveSearch].location == NSNotFound;
        report(@"dyld", @"dladdr(shadowcore)", hidden, fname);
    } else {
        report(@"dyld", @"dladdr(shadowcore)", YES, @"no image info returned");
    }

    // Control: CFGetTypeID lives in CoreFoundation, not /var/jb. (&main or
    // a local symbol would be the battery itself, which IS restricted.)
    memset(&info, 0, sizeof(info));

    if(dladdr((void*)&CFGetTypeID, &info) && info.dli_fname) {
        NSString* fname = [NSString stringWithUTF8String:info.dli_fname];
        BOOL clean = [fname rangeOfString:@"ShadowCore" options:NSCaseInsensitiveSearch].location == NSNotFound;
        report(@"dyld", @"dladdr(CFGetTypeID) control", clean, fname);
    } else {
        report(@"dyld", @"dladdr(CFGetTypeID) control", NO, @"no image info returned");
    }
}

// ---------------------------------------------------------------------------
// objc group (objc.x): class lookup / image enumeration. NSClassFromString
// and objc_getClass of "Shadow" must be nil/Nil; the Shadow.framework image
// must not surface its classes. Use the CANONICAL image path (the runtime
// records /private/preboot/... — a /var/jb alias may fail natively).
// ---------------------------------------------------------------------------

static void probeObjC(void) {
    BOOL classHidden = NSClassFromString(@"Shadow") == nil;
    report(@"objc", @"NSClassFromString(Shadow)", classHidden, @"");

    BOOL getClassHidden = objc_getClass("Shadow") == Nil;
    report(@"objc", @"objc_getClass(Shadow)", getClassHidden, @"");

    // Shared-cache class probes: the class-hiding predicate classifies the
    // RESULT's address via span ranges. System classes (NSString etc.) live in
    // the dyld shared cache, whose Class metadata sits in split/global ObjC
    // regions — if the span-based test misclassifies those, NSClassFromString
    // returns nil for EXTERNAL callers and UIKit/BoardServices asserts break
    // (observed on-device: ShadowHarness SIGTRAP in
    // +[BSMutableServiceInterface interfaceWithIdentifier:] because the
    // interface identifier class lookup returned nil).
    Class nsstr = NSClassFromString(@"NSString");
    BOOL nsstrOK = (nsstr != nil) && (nsstr == [NSString class]);
    report(@"objc", @"NSClassFromString(NSString)", nsstrOK, nsstr ? @"resolved" : @"NIL");

    Class nsobj = NSClassFromString(@"NSObject");
    BOOL nsobjOK = (nsobj != nil) && (nsobj == [NSObject class]);
    report(@"objc", @"NSClassFromString(NSObject)", nsobjOK, nsobj ? @"resolved" : @"NIL");

    // BoardServices is a private system framework; a root CLI may not have it
    // loaded at all, in which case a nil result is a probe artifact, not a
    // hiding failure. Load it first, then look the class up while loaded,
    // and only treat nil as FAIL when the framework actually loaded.
    void* bsHandle = dlopen("/System/Library/PrivateFrameworks/BoardServices.framework/BoardServices", RTLD_NOW | RTLD_LOCAL);

    if(bsHandle) {
        Class bsmutable = NSClassFromString(@"BSMutableServiceInterface");
        dlclose(bsHandle);
        report(@"objc", @"NSClassFromString(BSMutableServiceInterface)", bsmutable != nil, bsmutable ? @"resolved" : @"NIL");
    } else {
        skip(@"objc", @"NSClassFromString(BSMutableServiceInterface)", @"BoardServices not loaded in CLI context");
    }

    Class nsclass = objc_getClass("NSString");
    report(@"objc", @"objc_getClass(NSString)", nsclass != nil, nsclass ? @"resolved" : @"NIL");

    char canonicalPath[PATH_MAX];

    // The API keys on the LOADED IMAGE path (Shadow.framework/Shadow
    // executable), not the framework directory — a dir path can return NULL
    // natively, which would be a false PASS.
    if(!realpath([kShadowFwkBin fileSystemRepresentation], canonicalPath)) {
        skip(@"objc", @"objc_copyClassNamesForImage(shadowfwk)", @"realpath failed");
    } else {
        unsigned int count = 0;
        const char** names = objc_copyClassNamesForImage(canonicalPath, &count);

        if(!names) {
            report(@"objc", @"objc_copyClassNamesForImage(shadowfwk)", YES, @"nil (filtered)");
        } else {
            BOOL clean = YES;

            for(unsigned int i = 0; i < count; i++) {
                NSString* n = [NSString stringWithUTF8String:names[i]];

                if([n rangeOfString:@"Shadow" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    clean = NO;
                    break;
                }
            }

            free((void*)names);
            report(@"objc", @"objc_copyClassNamesForImage(shadowfwk)", clean, [NSString stringWithFormat:@"count=%u", count]);
        }
    }
}

// ---------------------------------------------------------------------------
// mem group (mem.x): vm_region answers must not include a region containing
// ShadowCore's code. Compare NUMERICALLY against the captured mach_header.
// NOTE: mach_vm_region takes the flavor BY VALUE (the pointer-form ABI
// passes a pointer where the kernel expects the int flavor and the call
// fails with KERN_INVALID_ARGUMENT — the mem.x production hook had the same
// bug until it was corrected there).
// ---------------------------------------------------------------------------

static void probeMem(const struct mach_header* shadowCoreHeader) {
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    BOOL foundShadowRegion = NO;
    uintptr_t target = (uintptr_t)shadowCoreHeader;
    uint32_t regions = 0;

    while(1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objName = MACH_PORT_NULL;
        vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;

        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                          flavor,
                                          (vm_region_info_t)&info, &infoCount, &objName);

        if(kr != KERN_SUCCESS) {
            if(regions == 0) {
                report(@"mem", @"vm_region hides ShadowCore", NO, [NSString stringWithFormat:@"first call failed (kr=%d) — ABI or hook issue", kr]);
            }

            break;
        }

        regions += 1;

        if(objName != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), objName);
        }

        if((uintptr_t)addr <= target && target < (uintptr_t)(addr + size)) {
            foundShadowRegion = YES;
            break;
        }

        addr += size;
    }

    if(regions == 0) {
        return;  // already reported
    }

    report(@"mem", @"vm_region hides ShadowCore", !foundShadowRegion, foundShadowRegion ? @"ShadowCore region visible" : [NSString stringWithFormat:@"%u regions walked, none contains ShadowCore", regions]);
}

// ---------------------------------------------------------------------------
// syscall group (syscall.x): csops CDHASH hiding. Precondition (unhooked
// baseline): CDHASH on self succeeds with a NONZERO hash. Post: the hook
// runs the original first, then converts the success into -1/EBADEXEC (the
// post buffer may still hold the real hash — only the return is asserted).
// Control: an invalid op must fail natively with EINVAL both before and
// after (proves the syscall path works). Never touches CS_OPS_MARKKILL.
// ---------------------------------------------------------------------------

static BOOL gCdhashBaselineOK = NO;
static uint8_t gCdhashBuf[20];

static void probeSyscallCsopsBaseline(void) {
    memset(gCdhashBuf, 0, sizeof(gCdhashBuf));
    errno = 0;
    int rc = csops(getpid(), CS_OPS_CDHASH, gCdhashBuf, sizeof(gCdhashBuf));

    BOOL nonzero = NO;

    for(size_t i = 0; i < sizeof(gCdhashBuf); i++) {
        if(gCdhashBuf[i] != 0) {
            nonzero = YES;
            break;
        }
    }

    if(rc != 0 || !nonzero) {
        skip(@"syscall", @"csops(CDHASH)", @"CDHASH precondition failed (unhooked baseline)");
        return;
    }

    gCdhashBaselineOK = YES;

    errno = 0;
    int ctrl = csops(getpid(), 0xFFFF, gCdhashBuf, sizeof(gCdhashBuf));
    BOOL ctrlOK = (ctrl == -1) && (errno == EINVAL);
    report(@"syscall", @"csops(invalid op) baseline", ctrlOK, [NSString stringWithFormat:@"rc=%d errno=%d", ctrl, errno]);
}

static void probeSyscallCsopsPost(void) {
    if(!gCdhashBaselineOK) {
        return;  // already skipped in baseline
    }

    errno = 0;
    int rc = csops(getpid(), CS_OPS_CDHASH, gCdhashBuf, sizeof(gCdhashBuf));
    BOOL hidden = (rc == -1) && (errno == EBADEXEC);
    report(@"syscall", @"csops(CDHASH)", hidden, [NSString stringWithFormat:@"rc=%d errno=%d", rc, errno]);

    errno = 0;
    int ctrl = csops(getpid(), 0xFFFF, gCdhashBuf, sizeof(gCdhashBuf));
    BOOL ctrlOK = (ctrl == -1) && (errno == EINVAL);
    report(@"syscall", @"csops(invalid op) control", ctrlOK, [NSString stringWithFormat:@"rc=%d errno=%d", ctrl, errno]);
}

// ---------------------------------------------------------------------------
// DeviceCheck group (DeviceCheck.x): DCDevice.isSupported fails closed (NO)
// when hooked. The framework MUST be dlopen'ed BEFORE ShadowCore — the ctor's
// descriptor install silently skips absent classes and never retries.
// performSelector-based (the tool links only Foundation; a static DCDevice
// class ref would need DeviceCheck at link time). isSupported returns BOOL
// in w0 — read the raw value via the pointer cast, NOT boolValue (a BOOL is
// not an object; messaging it crashes on YES).
// ---------------------------------------------------------------------------

static id gDCDevice = nil;

static void probeDeviceCheckPre(void) {
    Class dcClass = NSClassFromString(@"DCDevice");

    if(!dcClass) {
        skip(@"DeviceCheck", @"DCDevice.isSupported", @"DCDevice class unavailable after framework dlopen");
        return;
    }

    gDCDevice = [dcClass performSelector:NSSelectorFromString(@"currentDevice")];

    if(!gDCDevice) {
        skip(@"DeviceCheck", @"DCDevice.isSupported", @"currentDevice returned nil");
        return;
    }

    BOOL pre = (BOOL)(intptr_t)[gDCDevice performSelector:NSSelectorFromString(@"isSupported")];

    if(!pre) {
        skip(@"DeviceCheck", @"DCDevice.isSupported", @"precondition: isSupported != YES pre-hook");
        gDCDevice = nil;
        return;
    }

    report(@"DeviceCheck", @"DCDevice.isSupported baseline", YES, @"supported (unhooked)");
}

static void probeDeviceCheckPost(void) {
    if(!gDCDevice) {
        return;  // already skipped in pre
    }

    BOOL post = (BOOL)(intptr_t)[gDCDevice performSelector:NSSelectorFromString(@"isSupported")];
    report(@"DeviceCheck", @"DCDevice.isSupported", !post, post ? @"YES (not hooked)" : @"NO (hooked)");
}

// ---------------------------------------------------------------------------
// UIImage group (UIImage.x, Hook_Foundation@uikit): imageNamed: name-policy
// hiding. UIKit is dlopen'ed BEFORE ShadowCore (Run A ordering, proven
// on-device); the ctor's UIKit-load watcher replay (dylib.x:1042-1050)
// delivers the already-loaded UIKit and installs the UIImage group at ctor
// time. Baseline first (both fixture names load unhooked — a missing/corrupt
// protected fixture would otherwise false-PASS as "hidden"), then the post
// differential: the control image must still load (proves the API works)
// while the protected name ("Shadow.dylib.png" matches the shadow.dylib
// artifact pattern) must return nil (proves hiding). The battery is
// external, so isCallerExternal is satisfied. Fixture setup runs pre-dlopen
// — reading the icon from /var/jb is unfiltered there.
// ---------------------------------------------------------------------------

static NSBundle* gFixtureBundle = nil;
static NSString* const kFixtureBundleDir = @"/var/mobile/Documents/HookProbeAssets.bundle";

static NSString* shdw_fixtureIconSource(void) {
    for(NSString* path in @[ @"/var/jb/Library/PreferenceBundles/ShadowSettings.bundle",
                             @"/Library/PreferenceBundles/ShadowSettings.bundle" ]) {
        NSBundle* bundle = [NSBundle bundleWithPath:path];

        if(!bundle) {
            continue;
        }

        // Theos flattens bundle Resources into the bundle root — resolve via
        // pathForResource (handles both layouts) rather than a hardcoded
        // Resources/ subpath.
        NSString* icon = [bundle pathForResource:@"icon" ofType:@"png"];

        if(icon) {
            return icon;
        }
    }

    return nil;
}

static BOOL shdw_prepareImageFixture(NSString* srcIcon) {
    NSFileManager* fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    BOOL exists = [fm fileExistsAtPath:kFixtureBundleDir isDirectory:&isDir];

    if(!exists) {
        NSError* err = nil;

        if(![fm createDirectoryAtPath:kFixtureBundleDir withIntermediateDirectories:NO attributes:nil error:&err]) {
            return NO;
        }
    } else if(!isDir) {
        return NO;
    }

    for(NSString* name in @[ @"Shadow.dylib.png", @"control.png" ]) {
        NSString* dest = [kFixtureBundleDir stringByAppendingPathComponent:name];

        if(![fm fileExistsAtPath:dest]) {
            NSError* err = nil;

            if(![fm copyItemAtPath:srcIcon toPath:dest error:&err]) {
                return NO;
            }
        }
    }

    gFixtureBundle = [NSBundle bundleWithPath:kFixtureBundleDir];
    return gFixtureBundle != nil;
}

static BOOL shdw_uiImageLoads(NSString* name) {
    Class uiClass = NSClassFromString(@"UIImage");

    if(!uiClass) {
        return NO;
    }

    return [uiClass performSelector:NSSelectorFromString(@"imageNamed:inBundle:")
                         withObject:name withObject:gFixtureBundle] != nil;
}

// Pre-dlopen baseline (Run A ordering, proven on-device): UIKit is already
// loaded when ShadowCore's ctor runs, so the watcher replay installs the
// UIImage group at ctor time — the baseline below measures the UNHOOKED
// state. Both fixture names must load: a missing/corrupt protected fixture
// would otherwise false-PASS as "hidden" post-hook.
static void probeUIImagePre(void) {
    NSString* icon = shdw_fixtureIconSource();

    if(!icon) {
        skip(@"UIImage", @"imageNamed(inBundle:)", @"fixture icon unavailable");
        return;
    }

    if(!shdw_prepareImageFixture(icon)) {
        skip(@"UIImage", @"imageNamed(inBundle:)", @"fixture bundle unavailable");
        return;
    }

    BOOL protectedPre = shdw_uiImageLoads(@"Shadow.dylib.png");
    BOOL controlPre = shdw_uiImageLoads(@"control.png");

    if(!protectedPre || !controlPre) {
        skip(@"UIImage", @"imageNamed(inBundle:)", @"fixture images unavailable pre-hook");
        gFixtureBundle = nil;
        return;
    }

    report(@"UIImage", @"imageNamed(inBundle:) baseline", YES, @"both fixture images load (unhooked)");
}

static void probeUIImagePost(void) {
    if(!gFixtureBundle) {
        return;  // already skipped in pre
    }

    BOOL protectedHidden = !shdw_uiImageLoads(@"Shadow.dylib.png");
    BOOL controlVisible = shdw_uiImageLoads(@"control.png");

    report(@"UIImage", @"imageNamed(inBundle:)", protectedHidden && controlVisible,
           [NSString stringWithFormat:@"protected=%@ control=%@", protectedHidden ? @"hidden" : @"LEAKED", controlVisible ? @"loaded" : @"nil"]);
}

// ---------------------------------------------------------------------------
// NSFileManager group (NSFileManager.x) — tier-2 (detector-gated).
// ---------------------------------------------------------------------------

static void probeNSFileManager(void) {
    BOOL existsHidden = ![[NSFileManager defaultManager] fileExistsAtPath:kRestrictedDir];
    report(@"NSFileManager", @"fileExistsAtPath(restricted)", existsHidden, @"");

    BOOL readableHidden = ![[NSFileManager defaultManager] isReadableFileAtPath:kRestrictedDir];
    report(@"NSFileManager", @"isReadableFileAtPath(restricted)", readableHidden, @"");

    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:kRestrictedDir error:nil];
    report(@"NSFileManager", @"attributesOfItemAtPath(restricted)", attrs == nil, @"");

    NSArray* contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:kRestrictedDir error:nil];
    report(@"NSFileManager", @"contentsOfDirectoryAtPath(restricted)", contents == nil, @"");

    BOOL controlExists = [[NSFileManager defaultManager] fileExistsAtPath:kControlDir];
    report(@"NSFileManager", @"fileExistsAtPath(control)", controlExists, @"");
}

// ---------------------------------------------------------------------------
// NSURL group (NSURL.x) — tier-2 (detector-gated).
// ---------------------------------------------------------------------------

static void probeNSURL(void) {
    NSURL* restrictedURL = [NSURL fileURLWithPath:kRestrictedDir];

    NSError* err = nil;
    BOOL reachable = [restrictedURL checkResourceIsReachableAndReturnError:&err];
    report(@"NSURL", @"checkResourceIsReachable(restricted)", !reachable, err ? err.localizedDescription : @"");

    NSURL* ref = [restrictedURL fileReferenceURL];
    report(@"NSURL", @"fileReferenceURL(restricted)", ref == nil, ref ? ref.path : @"nil");

    NSURL* pathURL = [restrictedURL filePathURL];
    report(@"NSURL", @"filePathURL(restricted)", pathURL == nil, pathURL ? pathURL.path : @"nil");

    NSURL* controlURL = [NSURL fileURLWithPath:kControlDir];
    NSError* controlErr = nil;
    BOOL controlReachable = [controlURL checkResourceIsReachableAndReturnError:&controlErr];
    report(@"NSURL", @"checkResourceIsReachable(control)", controlReachable, controlErr ? controlErr.localizedDescription : @"");
}

// ---------------------------------------------------------------------------
// NSBundle group (NSBundle.x) — tier-2.
// ---------------------------------------------------------------------------

static void probeNSBundle(void) {
    NSBundle* restricted = [NSBundle bundleWithPath:kShadowFwk];
    report(@"NSBundle", @"bundleWithPath(shadowfwk)", restricted == nil, @"");

    NSBundle* main = [NSBundle mainBundle];
    report(@"NSBundle", @"mainBundle(control)", main != nil, @"");
}

// ---------------------------------------------------------------------------
// NSString / NSData / NSDictionary / NSArray groups — tier-2. Probes read
// REAL restricted files with native-readable content (a text/XML ruleset
// plist and the ShadowCore binary): the native read would SUCCEED and only
// the hook can produce nil. NSArray has no valid CLI probe: the only
// restricted plist (StandardRules.plist) is DICT-rooted, so parsing it as an
// array returns nil NATIVELY — a probe would false-pass. (The ShadowCore
// Mach-O parses as neither.)
// ---------------------------------------------------------------------------

static void probeContainerReads(void) {
    NSString* str = [NSString stringWithContentsOfFile:kShadowRuleset encoding:NSUTF8StringEncoding error:nil];
    report(@"NSString", @"stringWithContentsOfFile(ruleset)", str == nil, @"");

    NSData* data = [NSData dataWithContentsOfFile:kShadowCoreBin];
    report(@"NSData", @"dataWithContentsOfFile(shadowcore)", data == nil, @"");

    NSDictionary* dict = [NSDictionary dictionaryWithContentsOfFile:kShadowRuleset];
    report(@"NSDictionary", @"dictionaryWithContentsOfFile(ruleset)", dict == nil, @"");
}

// ---------------------------------------------------------------------------
// NSFileHandle group (NSFileHandle.x) — tier-2.
// ---------------------------------------------------------------------------

static void probeNSFileHandle(void) {
    NSFileHandle* fh = [NSFileHandle fileHandleForReadingAtPath:kShadowCoreBin];
    report(@"NSFileHandle", @"fileHandleForReadingAtPath(shadowcore)", fh == nil, @"");
}

// ---------------------------------------------------------------------------
// NSProcessInfo group (NSProcessInfo.x) — ctor envvars group.
// ---------------------------------------------------------------------------

static void probeNSProcessInfo(void) {
    NSDictionary* env = [[NSProcessInfo processInfo] environment];
    BOOL noInsertLibraries = [env objectForKey:@"DYLD_INSERT_LIBRARIES"] == nil;
    report(@"NSProcessInfo", @"environment sanitized", noInsertLibraries, [NSString stringWithFormat:@"keys=%lu", (unsigned long)[env count]]);
}

static void probeEnvironment(void) {
    const char* inserted = getenv("DYLD_INSERT_LIBRARIES");
    report(@"libc", @"getenv(DYLD_INSERT_LIBRARIES)", inserted == NULL,
           inserted ? [NSString stringWithUTF8String:inserted] : @"nil (filtered)");
}

// ---------------------------------------------------------------------------
// NSUserDefaults group (NSUserDefaults.x) — control: normal keys must work.
// ---------------------------------------------------------------------------

static void probeNSUserDefaults(void) {
    NSUserDefaults* defs = [NSUserDefaults standardUserDefaults];
    [defs setObject:@"hookprobe" forKey:@"hookprobe.canary"];
    BOOL roundtrip = [[defs objectForKey:@"hookprobe.canary"] isEqualToString:@"hookprobe"];
    [defs removeObjectForKey:@"hookprobe.canary"];
    report(@"NSUserDefaults", @"standard defaults roundtrip", roundtrip, @"");
}

// ---------------------------------------------------------------------------
// Groups that need a context a CLI cannot provide.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Groups with live hooks but context-sensitive probe surfaces. Pref-gated
// groups are probed only when the pref enables them; otherwise SKIP with the
// pref reason (the hook is legitimately not installed).
// ---------------------------------------------------------------------------

static void probeNSThread(void) {
    // NSThread.x filters Shadow/HookKit frames out of call stacks. The
    // battery's own stack (hkcheck) never contains Shadow frames, so the
    // honest check is that the APIs return well-formed filtered stacks and
    // no ShadowCore/HookKit symbol leaks into the symbol list.
    NSArray* addrs = [NSThread callStackReturnAddresses];
    NSArray* syms = [NSThread callStackSymbols];

    if(!addrs || !syms) {
        report(@"NSThread", @"callStack*", NO, @"nil result");
        return;
    }

    BOOL leaked = NO;

    for(NSString* line in syms) {
        if([line rangeOfString:@"ShadowCore" options:NSCaseInsensitiveSearch].location != NSNotFound
            || [line rangeOfString:@"HookKit" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            leaked = YES;
            break;
        }
    }

    report(@"NSThread", @"callStack* filtered", !leaked, [NSString stringWithFormat:@"frames=%lu", (unsigned long)[addrs count]]);
}

static void probeNSFileVersion(void) {
    // NSFileVersion.x returns nil for restricted item URLs.
    NSURL* restricted = [NSURL fileURLWithPath:kShadowCoreBin];
    NSFileVersion* hidden = [NSFileVersion currentVersionOfItemAtURL:restricted];
    report(@"NSFileVersion", @"currentVersionOfItemAtURL(restricted)", hidden == nil, hidden ? @"LEAKED" : @"nil (filtered)");

    // Control: an existing unrestricted file must still resolve.
    NSString* controlPath = @"/System/Library/CoreServices/SystemVersion.plist";
    NSFileVersion* control = [NSFileVersion currentVersionOfItemAtURL:[NSURL fileURLWithPath:controlPath]];
    report(@"NSFileVersion", @"currentVersionOfItemAtURL(control)", control != nil, control ? @"resolved" : @"nil");
}

static void probeNSFileWrapper(void) {
    // NSFileWrapper.x returns 0/nil for restricted item URLs.
    NSError* err = nil;
    NSFileWrapper* hidden = [[NSFileWrapper alloc] initWithURL:[NSURL fileURLWithPath:kShadowCoreBin] options:0 error:&err];
    report(@"NSFileWrapper", @"initWithURL(restricted)", hidden == nil, hidden ? @"LEAKED" : @"nil (filtered)");

    NSString* controlPath = @"/System/Library/CoreServices/SystemVersion.plist";
    NSFileWrapper* control = [[NSFileWrapper alloc] initWithURL:[NSURL fileURLWithPath:controlPath] options:0 error:&err];
    report(@"NSFileWrapper", @"initWithURL(control)", control != nil, control ? @"resolved" : @"nil");
}

static void probeMachBootstrap(void) {
    // mach.x hides restricted service names from bootstrap_look_up.
    mach_port_t hidden = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "me.jjolano.shadow.service", &hidden);
    BOOL hiddenDenied = (kr != KERN_SUCCESS) || (hidden == MACH_PORT_NULL);
    report(@"mach", @"bootstrap_look_up(restricted service)", hiddenDenied, [NSString stringWithFormat:@"kr=0x%x", kr]);

    // Control: an existing system service must still resolve.
    mach_port_t ctrl = MACH_PORT_NULL;
    kr = bootstrap_look_up(bootstrap_port, "com.apple.system.notification_center", &ctrl);
    BOOL controlOK = (kr == KERN_SUCCESS) && (ctrl != MACH_PORT_NULL);
    report(@"mach", @"bootstrap_look_up(control service)", controlOK, [NSString stringWithFormat:@"kr=0x%x", kr]);

    if(ctrl != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), ctrl);
    }
}

static void probeSandbox(void) {
    // sandbox.x denies sandbox_check for restricted paths.
    int r = sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH, [kRestrictedDir fileSystemRepresentation]);
    BOOL denied = (r == 1) || (r == -1);
    report(@"sandbox", @"sandbox_check(restricted)", denied, [NSString stringWithFormat:@"rc=%d", r]);

    int c = sandbox_check(getpid(), "file-read-data", SANDBOX_FILTER_PATH, [kControlDir fileSystemRepresentation]);
    report(@"sandbox", @"sandbox_check(control)", c == 0, [NSString stringWithFormat:@"rc=%d", c]);
}

static void probeSkippedGroups(void) {
    skip(@"UIApplication", @"canOpenURL", @"no UIApplication singleton in CLI context");
    skip(@"iokit", @"IOService lookups", @"hide returns empty iterator == stock no-match for absent restricted service class");
    skip(@"LSApplicationWorkspace", @"app enumeration", @"no restricted app installed on device (vacuous filter)");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

static const char* optionValue(int argc, char* argv[], const char* option) {
    for(int i = 1; i + 1 < argc; i++) {
        if(strcmp(argv[i], option) == 0) {
            return argv[i + 1];
        }
    }

    return NULL;
}

static void writeJSON(NSDictionary* value) {
    NSError* error = nil;
    NSData* data = [NSJSONSerialization dataWithJSONObject:value options:0 error:&error];

    if(!data) {
        fprintf(stderr, "hookprobe: failed to encode JSON: %s\n", error.localizedDescription.UTF8String);
        return;
    }

    fwrite(data.bytes, 1, data.length, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static BOOL reportArguments(int argc, char* argv[], const char** runID, const char** rowID,
                            const char** nonce, const char** revision, const char** requestedMode) {
    *runID = optionValue(argc, argv, "--run-id");
    *rowID = optionValue(argc, argv, "--row-id");
    *nonce = optionValue(argc, argv, "--nonce");
    *revision = optionValue(argc, argv, "--probe-revision");
    *requestedMode = optionValue(argc, argv, "--requested-mode");
    return *runID && *rowID && *nonce && *revision && *requestedMode;
}

static NSDictionary* reportEnvelope(NSString* producer, const char* runID, const char* rowID,
                                    const char* requestedMode, const char* nonce, const char* revision,
                                    NSDictionary* canary, NSDictionary* observations, int producerExit) {
    return @{
        @"schema_version" : @1,
        @"producer" : producer,
        @"run_id" : @(runID),
        @"row_id" : @(rowID),
        @"row_type" : @"jailbroken",
        @"requested_mode" : @(requestedMode),
        @"nonce" : @(nonce),
        @"probe_revision" : @(revision),
        @"canary" : canary,
        @"observations" : observations,
        @"producer_exit" : @(producerExit),
    };
}

static int reportRegressionMatrix(int argc, char* argv[], BOOL hooksLive) {
    const char *runID, *rowID, *nonce, *revision, *requestedMode;

    if(!reportArguments(argc, argv, &runID, &rowID, &nonce, &revision, &requestedMode)) {
        fprintf(stderr, "hookprobe: regression-matrix requires run, row, nonce, revision, and mode\n");
        return 64;
    }

    struct stat st;
    BOOL unrelated = stat([kControlDir fileSystemRepresentation], &st) == 0;
    NSDictionary* controls = @{ @"positive" : hooksLive ? @"PASS" : @"FAIL",
                                @"unrelated" : unrelated ? @"PASS" : @"FAIL" };
    BOOL canonicalComplete = NO;
    NSArray* regression = canonicalRegressionRows(&canonicalComplete);
    BOOL passed = hooksLive && unrelated && gFail == 0 && canonicalComplete;
    NSDictionary* observations = @{
        @"probes" : gProbeRows ? [gProbeRows copy] : @[],
        @"regression" : regression,
        @"controls" : controls,
        @"coverage" : @{ @"status" : canonicalComplete ? @"PASS" : @"FAIL",
                           @"canonical_count" : @(regression.count),
                           @"device_evidence" : @"named installed-hook witnesses; detailed contract assertions remain in the host ledger",
                           @"probe_summary" : @{ @"pass" : @(gPass), @"fail" : @(gFail), @"skip" : @(gSkip) } },
    };

    writeJSON(reportEnvelope(@"hookprobe-regression-matrix", runID, rowID, requestedMode, nonce, revision,
                             @{ @"status" : hooksLive ? @"PASS" : @"FAIL" }, observations, passed ? 0 : 1));
    return passed ? 0 : 1;
}

static BOOL isBackendAbsenceMode(const char* mode) {
    return mode && (strcmp(mode, "lifecycle-backend-absent") == 0 ||
                    strcmp(mode, "lifecycle-backend-absent-springboard-restart") == 0 ||
                    strcmp(mode, "lifecycle-backend-absent-userspace-reboot") == 0);
}

static BOOL missingPath(const char* path, int* outErrno) {
    errno = 0;
    BOOL missing = access(path, F_OK) != 0 && errno == ENOENT;

    if(outErrno) {
        *outErrno = errno;
    }

    return missing;
}

static int reportBackendAbsence(int argc, char* argv[], const char* mode) {
    const char* runID = optionValue(argc, argv, "--run-id");
    const char* rowID = optionValue(argc, argv, "--row-id");
    const char* nonce = optionValue(argc, argv, "--nonce");
    const char* revision = optionValue(argc, argv, "--probe-revision");
    const char* requestedMode = optionValue(argc, argv, "--requested-mode");

    if(!runID || !rowID || !nonce || !revision || !requestedMode) {
        fprintf(stderr, "hookprobe: lifecycle-backend-absent requires run, row, nonce, revision, and mode\n");
        return 64;
    }

    int rootlessErrno = 0, rootfulErrno = 0, rootlessLedgerErrno = 0, rootfulLedgerErrno = 0;
    int rootlessLogErrno = 0, rootfulLogErrno = 0;
    BOOL rootlessMissing = missingPath("/var/jb/usr/libexec/shadowd", &rootlessErrno);
    BOOL rootfulMissing = missingPath("/usr/libexec/shadowd", &rootfulErrno);
    BOOL rootlessLedgerMissing = missingPath("/var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger", &rootlessLedgerErrno);
    BOOL rootfulLedgerMissing = missingPath("/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger", &rootfulLedgerErrno);
    BOOL rootlessLogMissing = missingPath("/var/jb/var/log/shadowd.log", &rootlessLogErrno);
    BOOL rootfulLogMissing = missingPath("/var/log/shadowd.log", &rootfulLogErrno);
    mach_port_t service = MACH_PORT_NULL;
    kern_return_t serviceResult = bootstrap_look_up(bootstrap_port, "me.jjolano.shadow.service", &service);
    BOOL serviceMissing = serviceResult == BOOTSTRAP_UNKNOWN_SERVICE && service == MACH_PORT_NULL;
    BOOL restartMode = strcmp(mode, "lifecycle-backend-absent") != 0;
    const char* reconnect = optionValue(argc, argv, "--reconnect");
    BOOL reconnectPassed = !restartMode || (reconnect && strcmp(reconnect, "PASS") == 0);

    if(service != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), service);
    }

    BOOL passed = rootlessMissing && rootfulMissing && rootlessLedgerMissing && rootfulLedgerMissing &&
                  rootlessLogMissing && rootfulLogMissing && serviceMissing && reconnectPassed;
    NSArray* checks = @[
        @{ @"id" : @"rootless-payload", @"status" : rootlessMissing ? @"PASS" : @"FAIL", @"errno" : @(rootlessErrno) },
        @{ @"id" : @"rootful-payload", @"status" : rootfulMissing ? @"PASS" : @"FAIL", @"errno" : @(rootfulErrno) },
        @{ @"id" : @"rootless-ledger", @"status" : rootlessLedgerMissing ? @"PASS" : @"FAIL", @"errno" : @(rootlessLedgerErrno) },
        @{ @"id" : @"rootful-ledger", @"status" : rootfulLedgerMissing ? @"PASS" : @"FAIL", @"errno" : @(rootfulLedgerErrno) },
        @{ @"id" : @"rootless-activation-log", @"status" : rootlessLogMissing ? @"PASS" : @"FAIL", @"errno" : @(rootlessLogErrno) },
        @{ @"id" : @"rootful-activation-log", @"status" : rootfulLogMissing ? @"PASS" : @"FAIL", @"errno" : @(rootfulLogErrno) },
        @{ @"id" : @"mach-service", @"status" : serviceMissing ? @"PASS" : @"FAIL", @"kern_return" : @(serviceResult) },
    ];
    NSMutableDictionary* lifecycle = [@{ @"id" : @(mode), @"status" : passed ? @"PASS" : @"FAIL",
                                         @"restore" : @"PASS", @"checks" : checks } mutableCopy];

    if(restartMode) {
        lifecycle[@"reconnect"] = reconnectPassed ? @"PASS" : @"FAIL";
    }

    writeJSON(reportEnvelope(@"hookprobe-backend-absence", runID, rowID, requestedMode, nonce, revision,
                             @{ @"status" : passed ? @"PASS" : @"FAIL" }, @{ @"lifecycle" : @[ lifecycle ] },
                             passed ? 0 : 1));
    return passed ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Caller-identity battery
// ---------------------------------------------------------------------------

typedef int (*IdentityFixtureProbe)(const char*, const char*, shdw_identity_fixture_result_t*);
typedef NSDictionary* (*IdentitySnapshotMessage)(id, SEL, id, id);
typedef NSDictionary* (*IdentityImageMessage)(id, SEL, id);
typedef void (*IdentityScopeMessage)(id, SEL);

typedef struct {
    const char* id;
    const char* relativePath;
} IdentityFixtureVariant;

static const IdentityFixtureVariant kIdentityFixtureVariants[] = {
    { "copied", "copied.dylib" },
    { "symlinked", "symlinked.dylib" },
    { "matching-basename", "Shadow.dylib" },
    { "embedded", "Frameworks/Shadow.framework/Shadow" },
    { "case", "shadowcore.dylib" },
    { "prefix", "ShadowCoreCompat.dylib" },
    // Load this last so it is a true post-install, post-escalation image.
    { "late-loaded", "late.dylib" },
};

static NSDictionary* identityDictionary(id value) {
    return [value isKindOfClass:[NSDictionary class]] ? value : nil;
}

static BOOL identityBool(NSDictionary* dictionary, NSString* key) {
    id value = dictionary[key];
    return [value respondsToSelector:@selector(boolValue)] && [value boolValue];
}

static NSInteger identityInteger(NSDictionary* dictionary, NSString* key, NSInteger fallback) {
    id value = dictionary[key];
    return [value respondsToSelector:@selector(integerValue)] ? [value integerValue] : fallback;
}

static NSString* identityStatus(BOOL passed) {
    return passed ? @"PASS" : @"FAIL";
}

static void appendIdentityRegression(NSMutableArray* rows, NSString* variant, NSString* surface, NSString* status) {
    [rows addObject:@{ @"id" : [NSString stringWithFormat:@"identity.%@.%@", variant, surface],
                       @"status" : status }];
}

static BOOL identityFixtureDirectoryIsSafe(const char* path) {
    static const char prefix[] = "/var/jb/usr/lib/.shadow-hookprobe-identity-";
    size_t prefixLength = sizeof(prefix) - 1;

    if(!path || strncmp(path, prefix, prefixLength) != 0 || !path[prefixLength]) {
        return NO;
    }

    for(const unsigned char* cursor = (const unsigned char*)path + prefixLength; *cursor; cursor++) {
        if(!isalnum(*cursor) && *cursor != '.' && *cursor != '_' && *cursor != '-') {
            return NO;
        }
    }

    return YES;
}

static NSDictionary* identityCoreSnapshot(NSString* bundleID, NSString* scheme) {
    Class coordinator = objc_getRequiredClass("SHDWHookCoordinator");
    SEL selector = sel_registerName("shdw_identitySnapshotForBundleID:scheme:");

    if(!coordinator || ![coordinator respondsToSelector:selector]) {
        return nil;
    }

    id value = ((IdentitySnapshotMessage)objc_msgSend)((id)coordinator, selector, bundleID, scheme);
    return identityDictionary(value);
}

static NSDictionary* identityCoreImageForAddress(uintptr_t address) {
    Class coordinator = objc_getRequiredClass("SHDWHookCoordinator");
    SEL selector = sel_registerName("shdw_identityImageForAddress:");

    if(!coordinator || !address || ![coordinator respondsToSelector:selector]) {
        return nil;
    }

    id value = ((IdentityImageMessage)objc_msgSend)((id)coordinator, selector,
                                                     [NSValue valueWithPointer:(const void*)address]);
    return identityDictionary(value);
}

// `dlopen`/`dlsym` must run under the existing explicit internal scope only
// to stage filenames which the loader correctly hides from external callers.
// The scope exits before the fixture invokes any observed API, so its caller
// remains external and cannot borrow Shadow's truth privilege.
static IdentityFixtureProbe identityLoadFixture(NSString* path) {
    Class shadow = objc_getRequiredClass("Shadow");
    SEL enter = sel_registerName("shdwEnterInternalRead");
    SEL exit = sel_registerName("shdwExitInternalRead");
    IdentityFixtureProbe probe = NULL;

    if(!shadow || ![shadow respondsToSelector:enter] || ![shadow respondsToSelector:exit]) {
        return NULL;
    }

    ((IdentityScopeMessage)objc_msgSend)((id)shadow, enter);
    @try {
        void* handle = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);

        if(handle) {
            probe = (IdentityFixtureProbe)dlsym(handle, "shdw_identity_fixture_probe");

            if(!probe) {
                const char* error = dlerror();
                NSLog(@"[hookprobe] identity fixture symbol lookup failed %@: %s", path,
                      error ? error : "unknown error");
            }
        } else {
            const char* error = dlerror();
            NSLog(@"[hookprobe] identity fixture load failed %@: %s", path,
                  error ? error : "unknown error");
        }
    } @finally {
        ((IdentityScopeMessage)objc_msgSend)((id)shadow, exit);
    }

    return probe;
}

static NSString* identityBundleID(void) {
    NSArray<NSString*>* candidates = @[
        @"com.opa334.jailbreak", @"org.coolstar.sileo", @"xyz.willy.zebra",
        @"com.saurik.Cydia", @"science.xnu.underscore", @"com.llsc12.palera1nLoader"
    ];

    for(NSString* candidate in candidates) {
        NSDictionary* app = identityDictionary(identityCoreSnapshot(candidate, @"sileo")[@"app"]);

        if(identityBool(app, @"supported") && identityBool(app, @"present")) {
            return candidate;
        }
    }

    return candidates.firstObject;
}

static NSString* identityScheme(NSString* bundleID) {
    NSArray<NSString*>* candidates = @[@"sileo", @"zbra", @"cydia", @"filza", @"undecimus"];

    for(NSString* candidate in candidates) {
        NSDictionary* scheme = identityDictionary(identityCoreSnapshot(bundleID, candidate)[@"url_scheme"]);

        if(identityBool(scheme, @"supported") && identityInteger(scheme, @"result_count", 0) > 0) {
            return candidate;
        }
    }

    return candidates.firstObject;
}

static void probeLaunchServices(void) {
    NSString* bundleID = identityBundleID();
    NSString* scheme = identityScheme(bundleID);
    NSDictionary* canonical = identityCoreSnapshot(bundleID, scheme);
    NSDictionary* app = identityDictionary(canonical[@"app"]);
    NSDictionary* urlScheme = identityDictionary(canonical[@"url_scheme"]);
    Class proxyClass = objc_getRequiredClass("LSApplicationProxy");
    SEL proxySelector = sel_registerName("applicationProxyForIdentifier:");

    if(identityBool(app, @"supported") && identityBool(app, @"present") && proxyClass &&
       class_getClassMethod(proxyClass, proxySelector)) {
        typedef id (*ProxyMessage)(id, SEL, id);
        id proxy = ((ProxyMessage)objc_msgSend)((id)proxyClass, proxySelector, bundleID);
        report(@"LSApplicationWorkspace", @"applicationProxyForIdentifier(restricted)", proxy == nil,
               proxy ? @"restricted proxy leaked" : @"nil (filtered)");
    } else {
        skip(@"LSApplicationWorkspace", @"applicationProxyForIdentifier(restricted)",
             @"no internally visible restricted application fixture");
    }

    Class workspaceClass = objc_getRequiredClass("LSApplicationWorkspace");
    SEL workspaceSelector = sel_registerName("defaultWorkspace");
    SEL schemeSelector = sel_registerName("applicationsAvailableForHandlingURLScheme:");

    if(identityBool(urlScheme, @"supported") && identityInteger(urlScheme, @"result_count", 0) > 0 &&
       workspaceClass && class_getClassMethod(workspaceClass, workspaceSelector)) {
        typedef id (*WorkspaceMessage)(id, SEL);
        typedef id (*SchemeMessage)(id, SEL, id);
        id workspace = ((WorkspaceMessage)objc_msgSend)((id)workspaceClass, workspaceSelector);
        id values = workspace && [workspace respondsToSelector:schemeSelector]
            ? ((SchemeMessage)objc_msgSend)(workspace, schemeSelector, scheme) : nil;
        report(@"LSApplicationWorkspace", @"applicationsAvailableForHandlingURLScheme(restricted)",
               values && [values count] == 0,
               values ? [NSString stringWithFormat:@"count=%lu", (unsigned long)[values count]] : @"nil");
    } else {
        skip(@"LSApplicationWorkspace", @"applicationsAvailableForHandlingURLScheme(restricted)",
             @"no internally visible restricted URL-scheme fixture");
    }
}

static int reportIdentitySetupFailure(const char* runID, const char* rowID, const char* nonce,
                                      const char* revision, const char* requestedMode, NSString* reason) {
    writeJSON(reportEnvelope(@"hookprobe-identity", runID, rowID, requestedMode, nonce, revision,
                             @{ @"status" : @"FAIL" },
                             @{ @"identity" : @{ @"case_id" : @"identity", @"status" : @"FAIL", @"reason" : reason },
                                @"regression" : @[],
                                @"controls" : @{ @"positive" : @"FAIL", @"unrelated" : @"FAIL" } }, 1));
    return 1;
}

static int reportIdentity(int argc, char* argv[], BOOL hooksLive) {
    const char *runID, *rowID, *nonce, *revision, *requestedMode;
    const char* fixtureDirectory = optionValue(argc, argv, "--identity-fixture-dir");

    if(!reportArguments(argc, argv, &runID, &rowID, &nonce, &revision, &requestedMode)) {
        fprintf(stderr, "hookprobe: identity requires run, row, nonce, revision, and mode\n");
        return 64;
    }

    if(!identityFixtureDirectoryIsSafe(fixtureDirectory)) {
        return reportIdentitySetupFailure(runID, rowID, nonce, revision, requestedMode,
                                          @"invalid identity fixture directory");
    }

    NSString* directory = [NSString stringWithUTF8String:fixtureDirectory];
    NSString* bundleID = identityBundleID();
    NSString* scheme = identityScheme(bundleID);
    NSMutableArray* variants = [NSMutableArray array];
    NSMutableArray* regression = [NSMutableArray array];
    NSMutableSet* callerAddresses = [NSMutableSet set];

    for(NSUInteger index = 0; index < sizeof(kIdentityFixtureVariants) / sizeof(kIdentityFixtureVariants[0]); index++) {
        const IdentityFixtureVariant variant = kIdentityFixtureVariants[index];
        NSString* identifier = @(variant.id);
        NSString* requestedPath = [directory stringByAppendingPathComponent:@(variant.relativePath)];
        shdw_identity_fixture_result_t fixture = {0};
        IdentityFixtureProbe probe = identityLoadFixture(requestedPath);
        int fixtureRC = probe ? probe(bundleID.UTF8String, scheme.UTF8String, &fixture) : -1;
        NSDictionary* canonical = identityCoreSnapshot(bundleID, scheme);
        NSDictionary* image = fixtureRC == 0 ? identityCoreImageForAddress(fixture.caller_address) : nil;
        NSDictionary* canonicalIdentity = identityDictionary(canonical[@"identity"]);
        NSDictionary* canonicalFilesystem = identityDictionary(canonical[@"filesystem"]);
        NSDictionary* canonicalDyld = identityDictionary(canonical[@"dyld"]);
        NSDictionary* canonicalObjC = identityDictionary(canonical[@"objc"]);
        NSDictionary* canonicalProcess = identityDictionary(canonical[@"process"]);
        NSDictionary* canonicalApp = identityDictionary(canonical[@"app"]);
        NSDictionary* canonicalScheme = identityDictionary(canonical[@"url_scheme"]);
        BOOL canonicalFilesystemPass = identityInteger(canonicalFilesystem, @"result", -1) == 0;
        BOOL canonicalDyldPass = identityInteger(canonicalDyld, @"image_count", 0) > 0 &&
                                 identityInteger(canonicalDyld, @"runtime_image_count", 0) > 0;
        BOOL canonicalObjCPass = identityBool(canonicalObjC, @"shadow_present");
        BOOL canonicalProcessPass = identityBool(canonicalProcess, @"dyld_insert_present");
        BOOL appApplicable = identityBool(canonicalApp, @"supported") && identityBool(canonicalApp, @"present");
        BOOL schemeApplicable = identityBool(canonicalScheme, @"supported") &&
                                identityInteger(canonicalScheme, @"result_count", 0) > 0;
        BOOL filesystemPass = fixtureRC == 0 && canonicalFilesystemPass &&
                              fixture.stat_result != 0 && fixture.stat_errno == ENOENT;
        BOOL dyldPass = fixtureRC == 0 && canonicalDyldPass &&
                        fixture.dyld_image_count < (uint32_t)identityInteger(canonicalDyld, @"image_count", 0);
        BOOL objcPass = fixtureRC == 0 && canonicalObjCPass && fixture.objc_shadow_present == 0;
        BOOL processPass = fixtureRC == 0 && canonicalProcessPass && fixture.dyld_insert_present == 0;
        BOOL appPass = fixtureRC == 0 && appApplicable && fixture.bundle_proxy_present == 0;
        BOOL schemePass = fixtureRC == 0 && schemeApplicable && fixture.scheme_result_count == 0;
        NSMutableDictionary* surfaces = [@{
            @"filesystem" : identityStatus(filesystemPass),
            @"dyld" : identityStatus(dyldPass),
            @"objc" : identityStatus(objcPass),
            @"process" : identityStatus(processPass),
            @"app" : appApplicable ? identityStatus(appPass) : @"N/A",
            @"url-scheme" : schemeApplicable ? identityStatus(schemePass) : @"N/A",
        } mutableCopy];
        NSDictionary* fixtureResult = @{
            @"return" : @(fixtureRC),
            @"stat_result" : @(fixture.stat_result),
            @"stat_errno" : @(fixture.stat_errno),
            @"dyld_image_count" : @(fixture.dyld_image_count),
            @"objc_shadow_present" : @(fixture.objc_shadow_present),
            @"dyld_insert_present" : @(fixture.dyld_insert_present),
            @"bundle_proxy_present" : @(fixture.bundle_proxy_present),
            @"scheme_result_count" : @(fixture.scheme_result_count),
            @"caller_address" : [NSString stringWithFormat:@"0x%llx", (unsigned long long)fixture.caller_address],
        };
        NSMutableDictionary* row = [@{
            @"id" : identifier,
            @"requested_path" : requestedPath,
            @"image" : image ?: [NSNull null],
            @"canonical" : canonical ?: [NSNull null],
            @"fixture" : fixtureResult,
            @"surfaces" : surfaces,
        } mutableCopy];

        // Prove that every loaded variant got its own actual caller address;
        // a dyld de-duplication would otherwise make a filename-only test lie.
        BOOL mapped = [image[@"image_path"] isKindOfClass:[NSString class]] &&
                      identityDictionary(image[@"mapped_range"]) != nil &&
                      [image[@"caller_address"] isKindOfClass:[NSString class]] &&
                      !identityBool(image, @"canonical_runtime");
        NSString* caller = image[@"caller_address"];
        BOOL unique = mapped && ![callerAddresses containsObject:caller];

        if(unique) {
            [callerAddresses addObject:caller];
        }

        surfaces[@"provenance"] = identityStatus(unique);
        row[@"surfaces"] = surfaces;
        [variants addObject:row];
        appendIdentityRegression(regression, identifier, @"provenance", surfaces[@"provenance"]);
        appendIdentityRegression(regression, identifier, @"filesystem", surfaces[@"filesystem"]);
        appendIdentityRegression(regression, identifier, @"dyld", surfaces[@"dyld"]);
        appendIdentityRegression(regression, identifier, @"objc", surfaces[@"objc"]);
        appendIdentityRegression(regression, identifier, @"process", surfaces[@"process"]);

        if(appApplicable) {
            appendIdentityRegression(regression, identifier, @"app", surfaces[@"app"]);
        }

        if(schemeApplicable) {
            appendIdentityRegression(regression, identifier, @"url-scheme", surfaces[@"url-scheme"]);
        }

        if(!identityBool(canonicalIdentity, @"canonical_runtime")) {
            surfaces[@"canonical"] = @"FAIL";
        } else {
            surfaces[@"canonical"] = @"PASS";
        }
    }

    BOOL unrelated = stat(kControlDir.fileSystemRepresentation, &(struct stat){0}) == 0;
    BOOL passed = hooksLive && unrelated;

    for(NSDictionary* row in variants) {
        NSDictionary* surfaces = identityDictionary(row[@"surfaces"]);

        for(NSString* surface in @[ @"provenance", @"canonical", @"filesystem", @"dyld", @"objc", @"process" ]) {
            passed = passed && [surfaces[surface] isEqualToString:@"PASS"];
        }

        for(NSString* surface in @[ @"app", @"url-scheme" ]) {
            NSString* status = surfaces[surface];
            passed = passed && ([status isEqualToString:@"PASS"] || [status isEqualToString:@"N/A"]);
        }
    }

    NSDictionary* finalCanonical = identityCoreSnapshot(bundleID, scheme);
    writeJSON(reportEnvelope(@"hookprobe-identity", runID, rowID, requestedMode, nonce, revision,
                             @{ @"status" : passed ? @"PASS" : @"FAIL" },
                             @{
                                 @"identity" : @{ @"case_id" : @"identity", @"fixture_directory" : directory,
                                                   @"bundle_id" : bundleID, @"scheme" : scheme,
                                                   @"canonical" : finalCanonical ?: [NSNull null], @"variants" : variants },
                                 @"regression" : regression,
                                 @"controls" : @{ @"positive" : hooksLive ? @"PASS" : @"FAIL",
                                                   @"unrelated" : unrelated ? @"PASS" : @"FAIL" },
                             }, passed ? 0 : 1));
    return passed ? 0 : 1;
}

int main(int argc, char* argv[]) {
    @autoreleasepool {
        const char* mode = optionValue(argc, argv, "--mode");
        BOOL identityMode = mode && strcmp(mode, "identity") == 0;

        if(isBackendAbsenceMode(mode)) {
            return reportBackendAbsence(argc, argv, mode);
        }

        if(mode && strcmp(mode, "regression-matrix") != 0 && !identityMode) {
            fprintf(stderr, "hookprobe: unsupported mode: %s\n", mode);
            return 64;
        }

        gProbeRows = [NSMutableArray array];

        // Read the effective global prefs BEFORE any hook can influence the
        // read (the prefs plist lives in the mobile domain, outside the
        // restricted roots, but the values gate which groups we probe).
        gPrefs = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];

        // Resolve the EFFECTIVE settings the way ShadowCore's ctor does —
        // pre-dlopen, plain Foundation. The suite (initWithSuiteName:
        // kShadowPrefsPlist, same string ShadowSettings uses at Settings.m:
        // 24-25) reads the plist through cfprefsd, and registerDefaults
        // supplies the shipped defaults. This replicates
        // getPreferencesForIdentifier: (Settings.m:92-128) for a nil bundle
        // ID: shipped defaults, overlaid with stored suite values only when
        // Global_Enabled. Both baseline gating and probe gating use this one
        // model — the raw-plist model diverges from the ctor's resolution
        // on-device (URLScheme/EnvVars/DeviceCheck/LowLevelC/HideApps resolve
        // 0 in the CLI context), and a post-dlopen ShadowSettings query is
        // impossible from the battery (Shadow's NSClassFromString hiding,
        // objc.x:286-300, filters external callers).
        NSUserDefaults* ud = [[NSUserDefaults alloc] initWithSuiteName:kShadowPrefsPlist];
        [ud registerDefaults:shdw_defaultSettings()];
        NSMutableDictionary* eff = [shdw_defaultSettings() mutableCopy];

        if([ud boolForKey:@"Global_Enabled"]) {
            eff[@"App_Enabled"] = @YES;

            for(NSString* key in shdw_defaultSettings()) {
                id value = [ud objectForKey:key];

                if(value) {
                    eff[key] = value;  // stored ?? registered default (Settings.m:120)
                }
            }
        }

        gEffectivePrefs = [eff copy];

        BOOL syscallOn = prefsEnabled(@"Hook_Syscall");
        BOOL deviceCheckOn = prefsEnabled(@"Hook_DeviceCheck");
        // UIImage rides the Hook_Foundation@uikit group (dylib.x:475).
        BOOL uiImageOn = prefsEnabled(@"Hook_Foundation");

        // Pre-dlopen baselines: these must observe the UNHOOKED state, so
        // they run before ShadowCore loads.
        if(syscallOn) {
            probeSyscallCsopsBaseline();
        }

        if(deviceCheckOn) {
            // DeviceCheck must be loaded BEFORE ShadowCore: the ctor's
            // descriptor install silently skips absent classes — no late
            // retry. Keep the handle for the whole run (no dlclose).
            void* dcHandle = dlopen("/System/Library/Frameworks/DeviceCheck.framework/DeviceCheck", RTLD_NOW);

            if(dcHandle) {
                probeDeviceCheckPre();
            } else {
                skip(@"DeviceCheck", @"DCDevice.isSupported", @"DeviceCheck.framework dlopen failed");
            }
        }

        if(uiImageOn) {
            // Run A ordering (proven on-device): UIKit preloads BEFORE
            // ShadowCore — the ctor's UIKit-load watcher replay installs the
            // UIImage group for already-loaded UIKit at ctor time. Baseline
            // measured here, unhooked.
            void* uiHandle = dlopen("/System/Library/Frameworks/UIKit.framework/UIKit", RTLD_NOW);

            if(uiHandle) {
                probeUIImagePre();
            } else {
                skip(@"UIImage", @"imageNamed(inBundle:)", @"UIKit.framework dlopen failed");
            }
        }

        // Register the loader-safe add-image callback BEFORE dlopen: it stores
        // only raw mach_header pointers (no dladdr/Foundation/allocation —
        // work inside the callback during dlopen re-entered the hook
        // machinery and broke installation). ShadowCore's header is identified
        // after dlopen via LC_ID_DYLIB.
        _dyld_register_func_for_add_image(shadowcore_add_image);

        // The registration REPLAYS every already-loaded image (Foundation,
        // UIKit, DeviceCheck...) into the callback before ShadowCore loads,
        // filling the capture slots — the later ShadowCore notification would
        // be dropped. Discard the replay; the callback fires again when the
        // dlopen below maps ShadowCore.
        gCapturedCount = 0;

        // This is process-local evidence input, not an injection mechanism:
        // dyld reads DYLD_INSERT_LIBRARIES only at exec.  Both the canonical
        // matrix and the identity fixture prove that external getenv callers
        // are filtered while canonical Core code still sees the actual value.
        setenv("DYLD_INSERT_LIBRARIES", kShadowCoreBin.UTF8String, 1);

        // Load ShadowCore: the ctor installs the hook layer in-process,
        // exactly like ShadowTest. No spawn-injection dependency. The payload
        // lives at /usr/lib (rootless: /var/jb/usr/lib) — it is NOT a
        // DynamicLibraries tweak and must load only through this fixed path.
        void* handle = dlopen([kShadowCoreBin UTF8String], RTLD_NOW | RTLD_LOCAL);

        if(!handle) {
            NSLog(@"[hookprobe] WARN: primary ShadowCore dlopen failed (%s)", dlerror());
            handle = dlopen("/usr/lib/ShadowCore.dylib", RTLD_NOW | RTLD_LOCAL);
        }

        if(!handle) {
            NSLog(@"[hookprobe] FATAL: cannot dlopen ShadowCore.dylib (%s)", dlerror());
            if(mode) {
                if(identityMode) {
                    return reportIdentity(argc, argv, NO);
                }
                return reportRegressionMatrix(argc, argv, NO);
            }
            return 2;
        }

        usleep(500 * 1000);

        // NOTE: NULL here is a SETUP FAILURE, not an expected skip — the real
        // mapped header carries LC_ID_DYLIB and the capture depends on the
        // callback firing for the dlopen above. The dyld/mem probes FAIL.
        const struct mach_header* shadowCoreHeader = findShadowCoreHeader();

        if(!shadowCoreHeader) {
            NSLog(@"[hookprobe] WARN: ShadowCore header not captured (callback replay discard fix ineffective)");
        }

        BOOL hooksLive = probeCanary();

        if(!hooksLive) {
            NSLog(@"[hookprobe] hooks not active: restricted root is visible. Check Shadow is enabled for this bundle (prefs gate).");
        }

        if(identityMode) {
            return reportIdentity(argc, argv, hooksLive);
        }

        // Effective settings were resolved pre-dlopen (see main() top):
        // every prefsEnabled() below — including the post-dlopen probe
        // gating — consults that same model.
        BOOL fsOn = prefsEnabled(@"Hook_Filesystem") || prefsEnabled(@"Hook_LowLevelC");
        BOOL foundationOn = prefsEnabled(@"Hook_Foundation");
        BOOL envvarsOn = prefsEnabled(@"Hook_EnvVars");

        if(prefsEnabled(@"Hook_Filesystem")) {
            probeLibcFilesystem();
        } else {
            skip(@"libc", @"stat/access", @"Hook_Filesystem disabled");
        }

        if(prefsEnabled(@"Hook_LowLevelC")) {
            probeLibcLowLevel();
        } else {
            skip(@"libc", @"open/opendir", @"Hook_LowLevelC disabled");
        }

        probeDyld(shadowCoreHeader);
        probeObjC();

        if(shadowCoreHeader) {
            if(prefsEnabled(@"Hook_Memory")) {
                probeMem(shadowCoreHeader);
            } else {
                skip(@"mem", @"vm_region", @"Hook_Memory disabled");
            }
        } else {
            report(@"mem", @"vm_region", NO, @"ShadowCore header not captured (setup failure)");
        }

        // Post-dlopen gating consults the same pre-dlopen effective model as
        // the baselines (prefsEnabled → gEffectivePrefs): one model, both
        // sides — a group ShadowCore did not install can never false-FAIL.
        if(prefsEnabled(@"Hook_Syscall")) {
            probeSyscallCsopsPost();
        } else {
            skip(@"syscall", @"csops", @"Hook_Syscall disabled");
        }

        if(prefsEnabled(@"Hook_DeviceCheck")) {
            probeDeviceCheckPost();
        } else {
            skip(@"DeviceCheck", @"DCDevice.isSupported", @"Hook_DeviceCheck disabled");
        }

        if(prefsEnabled(@"Hook_Foundation")) {
            probeUIImagePost();
        } else {
            skip(@"UIImage", @"imageNamed(inBundle:)", @"Hook_Foundation disabled");
        }

        if(foundationOn) {
            probeNSFileManager();
            probeNSURL();
            probeNSBundle();
            probeContainerReads();
            // NSArray.x hooks arrayWithContentsOfFile: etc., but no
            // restricted fixture parses natively as an array (the ruleset is
            // dict-rooted) — a nil result would be native, not filtered.
            skip(@"NSArray", @"array reads", @"no stable CLI probe");
            probeNSFileHandle();
            // NSThread rides the Foundation@objc group (dylib.x:369).
            probeNSThread();
            // NSFileVersion/NSFileWrapper ride the Filesystem@objc group
            // (dylib.x:368), which installs with Hook_Filesystem.
            if(fsOn) {
                probeNSFileVersion();
                probeNSFileWrapper();
            } else {
                skip(@"NSFileVersion", @"versions", @"Hook_Filesystem disabled");
                skip(@"NSFileWrapper", @"wrappers", @"Hook_Filesystem disabled");
            }
        } else {
            skip(@"NSFileManager", @"tier-2 file APIs", @"Hook_Foundation disabled");
            skip(@"NSURL", @"URL APIs", @"Hook_Foundation disabled");
            skip(@"NSBundle", @"bundle APIs", @"Hook_Foundation disabled");
            skip(@"NSString", @"string reads", @"Hook_Foundation disabled");
            skip(@"NSData", @"data reads", @"Hook_Foundation disabled");
            skip(@"NSDictionary", @"dict reads", @"Hook_Foundation disabled");
            skip(@"NSArray", @"array reads", @"Hook_Foundation disabled");
            skip(@"NSFileHandle", @"handle reads", @"Hook_Foundation disabled");
            skip(@"NSThread", @"callStack*", @"Hook_Foundation disabled");
            skip(@"NSFileVersion", @"versions", @"Hook_Foundation disabled");
            skip(@"NSFileWrapper", @"wrappers", @"Hook_Foundation disabled");
        }

        if(envvarsOn) {
            probeEnvironment();
            probeNSProcessInfo();
        } else {
            skip(@"libc", @"getenv(DYLD_INSERT_LIBRARIES)", @"Hook_EnvVars disabled");
            skip(@"NSProcessInfo", @"environment", @"Hook_EnvVars disabled");
        }

        if(prefsEnabled(@"Hook_MachBootstrap")) {
            probeMachBootstrap();
        } else {
            skip(@"mach", @"bootstrap lookups", @"Hook_MachBootstrap disabled");
        }

        if(prefsEnabled(@"Hook_Sandbox")) {
            probeSandbox();
        } else {
            skip(@"sandbox", @"sandbox_check", @"Hook_Sandbox disabled");
        }

        probeNSUserDefaults();

        if(prefsEnabled(@"Hook_HideApps") || prefsEnabled(@"Hook_URLScheme")) {
            probeLaunchServices();
        } else {
            skip(@"LSApplicationWorkspace", @"application proxy", @"Hook_HideApps and Hook_URLScheme disabled");
            skip(@"LSApplicationWorkspace", @"URL-scheme lookup", @"Hook_HideApps and Hook_URLScheme disabled");
        }

        probeSkippedGroups();

        NSLog(@"[hookprobe] SUMMARY pass=%d fail=%d skip=%d hooksLive=%d", gPass, gFail, gSkip, hooksLive);

        if(mode) {
            return reportRegressionMatrix(argc, argv, hooksLive);
        }

        if(!hooksLive) {
            return 2;
        }

        return gFail == 0 ? 0 : 1;
    }
}
