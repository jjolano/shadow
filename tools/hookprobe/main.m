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
// Groups that cannot be probed from a CLI are reported SKIP with a reason:
//   vnode (daemon-mediated), UIApplication/UIImage (UIKit context),
//   mach/sandbox/iokit/syscall (kernel/launchd-context, device-specific),
//   NSThread/NSFileVersion/NSFileWrapper (covered by the URL/file groups).

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <bootstrap.h>
#import <sandbox.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <fcntl.h>
#import <dirent.h>
#import <unistd.h>

// The 16.5 SDK stubs out mach_vm.h ("unsupported") — declare the prototype
// manually. The flavor is BY VALUE (a pointer-form prototype passes a
// pointer where the kernel expects the int flavor and the call fails with
// KERN_INVALID_ARGUMENT; the production mem.x hook had this bug until
// corrected there).
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* infoCnt, mach_port_t* object_name);

// ---------------------------------------------------------------------------
// Result ledger
// ---------------------------------------------------------------------------

static int gPass = 0;
static int gFail = 0;
static int gSkip = 0;

static void report(NSString* group, NSString* name, BOOL ok, NSString* detail) {
    if(ok) {
        gPass += 1;
        NSLog(@"[hookprobe] PASS %@::%@ %@", group, name, detail);
    } else {
        gFail += 1;
        NSLog(@"[hookprobe] FAIL %@::%@ %@", group, name, detail);
    }
}

static void skip(NSString* group, NSString* name, NSString* reason) {
    gSkip += 1;
    NSLog(@"[hookprobe] SKIP %@::%@ (%@)", group, name, reason);
}

// ---------------------------------------------------------------------------
// Probe paths — real, existing, restricted files only. A synthesized
// nonexistent path would pass every probe trivially.
// ---------------------------------------------------------------------------

static NSString* const kRestrictedDir = @"/var/jb";
static NSString* const kShadowCoreBin = @"/var/jb/usr/lib/TweakInject/ShadowCore.dylib";
static NSString* const kShadowRuleset = @"/var/jb/Library/Shadow/Rulesets/StandardRules.plist";
static NSString* const kShadowFwk    = @"/var/jb/Library/Frameworks/Shadow.framework";
static NSString* const kShadowFwkBin = @"/var/jb/Library/Frameworks/Shadow.framework/Shadow";
static NSString* const kControlDir   = @"/var/mobile/Documents";

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
// The plist is in the mobile prefs domain (not /var/jb — that path is
// restricted and the read itself would be filtered); it must be read BEFORE
// dlopen so the value is never influenced by the hooks. When the plist is
// missing, the SHIPPED defaults apply (Foundation/Memory ship OFF — the
// identity groups are unconditional).
// ---------------------------------------------------------------------------

static NSDictionary* gPrefs = nil;

static BOOL prefsEnabled(NSString* key) {
    id value = [gPrefs objectForKey:key];

    if(value) {
        return [value boolValue];
    }

    if([key isEqualToString:@"Hook_Foundation"] || [key isEqualToString:@"Hook_Memory"]) {
        return NO;  // shipped default: OFF
    }

    return YES;
}

// ---------------------------------------------------------------------------
// libc group (libc.x): stat/access/open/opendir — tier 1, ctor-installed.
// ---------------------------------------------------------------------------

static void probeLibc(void) {
    struct stat st;

    errno = 0;
    BOOL statHidden = stat([kRestrictedDir fileSystemRepresentation], &st) != 0 && errno == ENOENT;
    report(@"libc", @"stat(restricted)", statHidden, [NSString stringWithFormat:@"errno=%d", errno]);

    errno = 0;
    BOOL accessHidden = access([kRestrictedDir fileSystemRepresentation], F_OK) != 0 && errno == ENOENT;
    report(@"libc", @"access(restricted)", accessHidden, [NSString stringWithFormat:@"errno=%d", errno]);

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

    errno = 0;
    BOOL controlVisible = stat([kControlDir fileSystemRepresentation], &st) == 0;
    report(@"libc", @"stat(control)", controlVisible, [NSString stringWithFormat:@"errno=%d", errno]);
}

// ---------------------------------------------------------------------------
// ShadowCore header capture: loader-safe add-image callback. The callback
// stores ONLY raw mach_header pointers (no dladdr, no Foundation, no
// allocation — work inside the callback during dlopen/ctor re-entered the
// hook machinery and broke installation). ShadowCore is identified AFTER
// dlopen by parsing each header's LC_ID_DYLIB basename. If the replay is
// filtered (Shadow's own hooked registration drops ShadowCore), fall back to
// the dlopen HANDLE itself: on Darwin the handle dlopen returns for a dylib
// IS that image's mach_header (documented behavior — dladdr(handle) and
// dlsym(handle, ...) both rely on it), so the handle doubles as the header
// without any dyld API call.
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

// NOTE: handle may be NULL (dlopen failed) — caller checks.
static const struct mach_header* shadowcoreHeaderFromHandle(void* handle) {
    if(!handle) {
        return NULL;
    }

    // Darwin dlopen returns the image's mach_header as the handle for
    // dylibs; verify before trusting it.
    const struct mach_header* h = (const struct mach_header*)handle;

    if(shdw_is_shadowcore_header(h)) {
        return h;
    }

    return NULL;
}

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
// unhooked before the ctor ran.
// ---------------------------------------------------------------------------

static void probeDyld(const struct mach_header* shadowCoreHeader) {
    if(!shadowCoreHeader) {
        // Shadow's own hooked _dyld_register_func_for_add_image filters the
        // replay, so ShadowCore's header is unreachable through the public
        // dyld API once hooks are live — that IS the hiding behavior under
        // test, not a probe failure. SKIP instead of FAIL.
        skip(@"dyld", @"dladdr(shadowcore)", @"ShadowCore header not capturable via public dyld API (filtered — expected)");
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
// the hook can produce nil. (UTF-8-reading a Mach-O into a string or
// parsing a binary as an array returns nil natively — those would be false
// passes, so NSArray has no valid CLI probe and is skipped.)
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
    skip(@"vnode", @"vnode-layer hiding", @"daemon-mediated; covered by shadowd");
    skip(@"UIApplication", @"canOpenURL", @"requires UIKit app context");
    skip(@"UIImage", @"image loading", @"requires UIKit app context");
    skip(@"iokit", @"IOService lookups", @"device-specific service classes");
    skip(@"syscall", @"syscall/csops", @"kernel-context, device-specific");
    skip(@"DeviceCheck", @"device checks", @"private API, no stable probe");
    skip(@"LSApplicationWorkspace", @"app enumeration", @"private API, tier-2 gated");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    (void) argc;
    (void) argv;

    @autoreleasepool {
        // Read the effective global prefs BEFORE any hook can influence the
        // read (the prefs plist lives in the mobile domain, outside the
        // restricted roots, but the values gate which groups we probe).
        gPrefs = [NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];

        // Register the loader-safe add-image callback BEFORE dlopen: it stores
        // only raw mach_header pointers (no dladdr/Foundation/allocation —
        // work inside the callback during dlopen re-entered the hook
        // machinery and broke installation). ShadowCore's header is identified
        // after dlopen via LC_ID_DYLIB.
        _dyld_register_func_for_add_image(shadowcore_add_image);

        // Load ShadowCore: the ctor installs the hook layer in-process,
        // exactly like ShadowTest. No spawn-injection dependency.
        void* handle = dlopen("/var/jb/usr/lib/TweakInject/ShadowCore.dylib", RTLD_NOW | RTLD_LOCAL);

        if(!handle) {
            handle = dlopen("/usr/lib/TweakInject/ShadowCore.dylib", RTLD_NOW | RTLD_LOCAL);
        }

        if(!handle) {
            NSLog(@"[hookprobe] FATAL: cannot dlopen ShadowCore.dylib (%s)", dlerror());
            return 2;
        }

        usleep(500 * 1000);

        const struct mach_header* shadowCoreHeader = findShadowCoreHeader();

        if(!shadowCoreHeader) {
            // The add-image replay is filtered by Shadow's own hooked
            // registration — fall back to the dlopen handle, which IS the
            // image's mach_header on Darwin.
            shadowCoreHeader = shadowcoreHeaderFromHandle(handle);

            if(!shadowCoreHeader) {
                NSLog(@"[hookprobe] WARN: ShadowCore header not captured (add-image replay filtered; dlopen handle did not validate)");
            }
        }

        BOOL hooksLive = probeCanary();

        if(!hooksLive) {
            NSLog(@"[hookprobe] hooks not active: restricted root is visible. Check Shadow is enabled for this bundle (prefs gate).");
        }

        BOOL fsOn = prefsEnabled(@"Hook_Filesystem") || prefsEnabled(@"Hook_LowLevelC");
        BOOL foundationOn = prefsEnabled(@"Hook_Foundation");
        BOOL envvarsOn = prefsEnabled(@"Hook_EnvVars");

        if(fsOn) {
            probeLibc();
        } else {
            skip(@"libc", @"C file hooks", @"Hook_Filesystem/Hook_LowLevelC disabled");
        }

        probeDyld(shadowCoreHeader);
        probeObjC();

        if(shadowCoreHeader) {
            probeMem(shadowCoreHeader);
        } else {
            skip(@"mem", @"vm_region", @"ShadowCore header not captured");
        }

        if(foundationOn) {
            probeNSFileManager();
            probeNSURL();
            probeNSBundle();
            probeContainerReads();
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
            probeNSProcessInfo();
        } else {
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
        probeSkippedGroups();

        NSLog(@"[hookprobe] SUMMARY pass=%d fail=%d skip=%d hooksLive=%d", gPass, gFail, gSkip, hooksLive);

        if(!hooksLive) {
            return 2;
        }

        return gFail == 0 ? 0 : 1;
    }
}
