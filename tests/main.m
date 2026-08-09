// Shadow decision-engine test harness (host, no device).
//
// Builds the real Shadow.framework decision sources (Core, Backend, Ruleset,
// Core+Utilities) against the host Foundation with a stubbed RootBridge, then
// stages itself into a temp dir shaped like an app on a jailbroken device:
//
//   <work>/Harness.app/harness          the running binary (bundlePath ends
//                                       in .app, so hasAppSandbox is YES and
//                                       the resolve-before-exempt branch of
//                                       isPathRestricted: is exercised)
//   <work>/fs/jb/...                    fixture jbroot tree backing the
//                                       virtual filesystem (see fsinterpose.c)
//   <work>/<jb|root>/Library/Shadow/Rulesets/   staged rulesets
//   <work>/shdw-app/restricted-target   real file the rooted sandbox symlink
//                                       resolves to
//
// Run modes: no args runs both rooted and rootless modes; --rooted/--rootless
// pick one; --detect runs the detector-probe battery instead of the unit
// assertions. Every decision is made by the real engine — this file only
// stages fixtures and checks verdicts.
//
// Virtual filesystem: on Linux the harness links with -Wl,--wrap=access
// -Wl,--wrap=realpath and installs the fixture jbroot (shdw_fs_set_jbroot),
// so the engine's literal "/var/jb"-prefixed access()/realpath() gate calls
// resolve into the fixture tree — rootless mode behaves exactly as on a
// device (file present → gate passes → engine decides; absent → gate
// blocks). The single irreducible host limitation: rooted-mode /usr/lib
// read gates probe the real host /usr/lib, which never holds jailbreak
// files — those assertions use C0-1 write probes (gate-skipping,
// device-accurate) and rootless read probes instead.

#import <Foundation/Foundation.h>
#import <Shadow.h>
#import <RootBridge.h>
#import "RootBridgeStub.h"
#import "fsinterpose.h"

#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <sys/wait.h>
#import <fcntl.h>
#import <limits.h>

// Edge-case fuzzer (Fuzz.m): probes the engine with mutated inputs and
// asserts invariants; returns the number of findings (0 = clean).
int shdw_fuzz_run(NSUInteger iters, unsigned seed);
int shdw_afuzz_run(NSUInteger variantsPerSeed, unsigned seed);

static BOOL gRootless = NO;
static BOOL gDetect = NO;
static BOOL gAdversary = NO;
static BOOL gDetector = NO;
static BOOL gBenign = NO;
static BOOL gShipped = NO;
static BOOL gFuzz = NO;
static BOOL gAFuzz = NO;
static int gPass = 0;
static int gFail = 0;

#define CHECK(_cond, _name) do { \
    if(_cond) { gPass++; } else { gFail++; printf("FAIL: %s\n", _name); } \
} while(0)

static NSDictionary* writeOptions(void) {
    return @{kShadowRestrictionOperation : kShadowRestrictionOpWrite};
}

static NSString* harnessWorkDir(void) {
    NSString* exe = [[[NSProcessInfo processInfo] arguments] objectAtIndex:0];
    NSString* appDir = [exe stringByDeletingLastPathComponent];
    return [appDir stringByDeletingLastPathComponent];
}

static Shadow* shdw(void) {
    return [Shadow sharedInstance];
}

static void expectRestricted(NSString* name, NSString* path) {
    BOOL r = [shdw() isPathRestricted:path];

    if(r) {
        gPass++;
    } else {
        gFail++;
        printf("FAIL: %s (expected restricted, got allowed: %s)\n", [name UTF8String], [path UTF8String]);
    }
}

static void expectAllowed(NSString* name, NSString* path) {
    BOOL r = [shdw() isPathRestricted:path];

    if(!r) {
        gPass++;
    } else {
        gFail++;
        printf("FAIL: %s (expected allowed, got restricted: %s)\n", [name UTF8String], [path UTF8String]);
    }
}

static void expectRestrictedWrite(NSString* name, NSString* path) {
    BOOL r = [shdw() isPathRestricted:path options:writeOptions()];

    if(r) {
        gPass++;
    } else {
        gFail++;
        printf("FAIL: %s (expected write-denied, got allowed: %s)\n", [name UTF8String], [path UTF8String]);
    }
}

static void expectAllowedOpts(NSString* name, NSString* path, NSDictionary* options) {
    BOOL r = [shdw() isPathRestricted:path options:options];

    if(!r) {
        gPass++;
    } else {
        gFail++;
        printf("FAIL: %s (expected allowed, got restricted: %s)\n", [name UTF8String], [path UTF8String]);
    }
}

// ---------------------------------------------------------------------------
// Staging (parent process): build <work> and re-exec into Harness.app.
// ---------------------------------------------------------------------------

static BOOL copyTree(NSString* src, NSString* dst) {
    NSFileManager* fm = [NSFileManager defaultManager];

    if(![fm createDirectoryAtPath:dst withIntermediateDirectories:YES attributes:nil error:nil]) {
        return NO;
    }

    NSArray* items = [fm contentsOfDirectoryAtPath:src error:nil];

    for(NSString* item in items) {
        NSString* s = [src stringByAppendingPathComponent:item];
        NSString* d = [dst stringByAppendingPathComponent:item];
        BOOL isDir = NO;

        [fm fileExistsAtPath:s isDirectory:&isDir];

        if(isDir) {
            if(!copyTree(s, d)) {
                return NO;
            }
        } else if(![fm copyItemAtPath:s toPath:d error:nil]) {
            return NO;
        }
    }

    return YES;
}

static BOOL copyPlistFiles(NSString* srcDir, NSString* dstDir) {
    NSFileManager* fm = [NSFileManager defaultManager];

    if(![fm createDirectoryAtPath:dstDir withIntermediateDirectories:YES attributes:nil error:nil]) {
        return NO;
    }

    NSArray* items = [fm contentsOfDirectoryAtPath:srcDir error:nil];

    for(NSString* item in items) {
        if(![[item pathExtension] isEqualToString:@"plist"]) {
            continue;
        }

        if(![fm copyItemAtPath:[srcDir stringByAppendingPathComponent:item]
                        toPath:[dstDir stringByAppendingPathComponent:item]
                         error:nil]) {
            return NO;
        }
    }

    return YES;
}

// The parent stages <work> and execs itself (as <work>/Harness.app/harness)
// once per mode. The child skips staging entirely (SHADW_HARNESS_STAGED).
// Mode comes from the ARGV (the fork child inherits the parent's globals,
// which reflect the parent's own invocation — not the mode being staged).
static int stageAndExec(int argc, const char** argv) {
    for(int i = 1; i < argc && argv[i]; i++) {
        if(strcmp(argv[i], "--rootless") == 0) {
            gRootless = YES;
        } else if(strcmp(argv[i], "--detect") == 0) {
            gDetect = YES;
        } else if(strcmp(argv[i], "--adversary") == 0) {
            gAdversary = YES;
        } else if(strcmp(argv[i], "--detector") == 0) {
            gDetector = YES;
        } else if(strcmp(argv[i], "--benign") == 0) {
            gBenign = YES;
        } else if(strcmp(argv[i], "--shipped") == 0) {
            gShipped = YES;
        } else if(strcmp(argv[i], "--fuzz") == 0) {
            gFuzz = YES;
        } else if(strcmp(argv[i], "--afuzz") == 0) {
            gAFuzz = YES;
        }
    }

    // The detector/benign/adversarial-fuzz batteries simulate a rootless
    // jailbreak (virtual FS + shadow filter); the fuzzer and the shipped
    // ruleset battery run both modes.
    if(gDetector || gBenign || gAFuzz) {
        gRootless = YES;
    }

    NSFileManager* fm = [NSFileManager defaultManager];

    NSString* srcDir = [NSString stringWithUTF8String:argv[0]];

    if(![srcDir isAbsolutePath]) {
        srcDir = [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:srcDir];
    }

    srcDir = [[srcDir stringByResolvingSymlinksInPath] stringByDeletingLastPathComponent];

    NSString* work = [NSTemporaryDirectory() stringByAppendingPathComponent:
        [NSString stringWithFormat:@"shdw-harness-%d-%s", getpid(), gRootless ? "rootless" : "rooted"]];

    NSString* rulesetsSrc = (gDetect || gDetector || gShipped)
        ? [srcDir stringByAppendingPathComponent:@"../Shadow.framework/layout/Library/Shadow/Rulesets"]
        : [srcDir stringByAppendingPathComponent:@"fixtures/rulesets"];
    NSString* rulesetsDst = [work stringByAppendingPathComponent:
        (gRootless ? @"jb/Library/Shadow/Rulesets" : @"root/Library/Shadow/Rulesets")];

    if(!copyTree([srcDir stringByAppendingPathComponent:@"fixtures/fs"], [work stringByAppendingPathComponent:@"fs"])
        || !copyPlistFiles(rulesetsSrc, rulesetsDst)) {
        fprintf(stderr, "harness: staging failed\n");
        return 1;
    }

    if(!gDetect) {
        // Real file the sandbox symlink resolves to; the staged ruleset
        // blacklists this exact path so the resolve-before-exempt branch can
        // be asserted against a target that really exists on the host.
        NSString* target = [work stringByAppendingPathComponent:@"shdw-app/restricted-target"];

        if(![fm createDirectoryAtPath:[target stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil]
            || ![[NSData data] writeToFile:target atomically:YES]) {
            fprintf(stderr, "harness: sandbox target staging failed\n");
            return 1;
        }

        NSDictionary* sandboxRules = @{
            @"RulesetInfo" : @{@"Name" : @"Test Sandbox", @"Author" : @"harness"},
            @"BlacklistExactPaths" : @[target]
        };

        if(![sandboxRules writeToFile:[rulesetsDst stringByAppendingPathComponent:@"006-Sandbox.plist"] atomically:YES]) {
            fprintf(stderr, "harness: sandbox ruleset staging failed\n");
            return 1;
        }

        // Benign-app container: a normal app's files, used by the benign
        // battery to verify Shadow leaves standard app usage untouched.
        NSString* container = [work stringByAppendingPathComponent:@"app-container"];
        NSString* cDocs = [container stringByAppendingPathComponent:@"Documents"];
        NSString* cPrefs = [container stringByAppendingPathComponent:@"Library/Preferences"];
        NSString* cTmp = [container stringByAppendingPathComponent:@"tmp"];

        if(![fm createDirectoryAtPath:cDocs withIntermediateDirectories:YES attributes:nil error:nil]
            || ![fm createDirectoryAtPath:cPrefs withIntermediateDirectories:YES attributes:nil error:nil]
            || ![fm createDirectoryAtPath:cTmp withIntermediateDirectories:YES attributes:nil error:nil]
            || ![[@"hello from the app" dataUsingEncoding:NSUTF8StringEncoding]
                writeToFile:[cDocs stringByAppendingPathComponent:@"notes.txt"] atomically:YES]
            || ![[@"com.example.app" dataUsingEncoding:NSUTF8StringEncoding]
                writeToFile:[cPrefs stringByAppendingPathComponent:@"com.example.app.plist"] atomically:YES]
            || ![[@"not a jailbreak artifact" dataUsingEncoding:NSUTF8StringEncoding]
                writeToFile:[container stringByAppendingPathComponent:@"ssh"] atomically:YES]) {
            fprintf(stderr, "harness: app-container staging failed\n");
            return 1;
        }
    }

    NSString* appDir = [work stringByAppendingPathComponent:@"Harness.app"];
    NSString* exePath = [appDir stringByAppendingPathComponent:@"harness"];

    // Absolute destination: the symlink is resolved relative to the temp
    // app dir, so a relative argv[0] ("tests/harness") would dangle.
    NSString* absExe = [srcDir stringByAppendingPathComponent:[[NSString stringWithUTF8String:argv[0]] lastPathComponent]];

    if(![fm createDirectoryAtPath:appDir withIntermediateDirectories:YES attributes:nil error:nil]
        || ![fm createSymbolicLinkAtPath:exePath withDestinationPath:absExe error:nil]) {
        fprintf(stderr, "harness: app staging failed\n");
        return 1;
    }

    setenv("SHADW_HARNESS_STAGED", "1", 1);

    char* newargv[8];
    int n = 0;
    newargv[n++] = (char*)[exePath UTF8String];

    if(gRootless) {
        newargv[n++] = (char*)"--rootless";
    } else {
        newargv[n++] = (char*)"--rooted";
    }

    if(gDetect) {
        newargv[n++] = (char*)"--detect";
    } else if(gAdversary) {
        newargv[n++] = (char*)"--adversary";
    } else if(gDetector) {
        newargv[n++] = (char*)"--detector";
    } else if(gBenign) {
        newargv[n++] = (char*)"--benign";
    } else if(gShipped) {
        newargv[n++] = (char*)"--shipped";
    } else if(gFuzz) {
        newargv[n++] = (char*)"--fuzz";
    } else if(gAFuzz) {
        newargv[n++] = (char*)"--afuzz";
    }

    newargv[n] = NULL;
    execv([exePath UTF8String], newargv);
    perror("harness: execv");
    return 1;
}

// ---------------------------------------------------------------------------
// Unit test groups
// ---------------------------------------------------------------------------

static void testBasics(void) {
    printf("[tests] basics\n");
    CHECK(![shdw() isPathRestricted:nil], "nil path allowed");
    CHECK(![shdw() isPathRestricted:@""], "empty path allowed");
    CHECK(![shdw() isPathRestricted:@"/"], "root path allowed");
    CHECK(![shdw() isPathRestricted:@"~definitely-not-a-user/foo"], "unresolvable tilde allowed");

    // relative-path resolution via workingDir (assert via /var paths, which
    // reach the engine in both modes)
    CHECK(![shdw() isPathRestricted:@"Library/Preferences/x" options:@{kShadowRestrictionWorkingDir : @"/var/mobile"}], "relative path resolved via workingDir");
    CHECK(![shdw() isPathRestricted:@"../usr/bin/ssh" options:@{kShadowRestrictionWorkingDir : @"/"}], "dot-dot path standardized, whitelisted");

    if(!gRootless) {
        CHECK([shdw() isPathRestricted:@"fstab" options:@{kShadowRestrictionWorkingDir : @"/usr/sbin"}], "relative fstab resolved via workingDir (rooted)");
    }
}

static void testRulesets(void) {
    printf("[tests] ruleset decisions\n");

    // exact blacklist / whitelist precedence. Engine semantics: whitelist
    // beats an exact blacklist on the path itself, and prefix rules cover
    // the prefix plus its direct children; parent-dir recursion restricts a
    // path under a blacklisted (and unwhitelisted) parent regardless.
    expectRestricted(@"exact blacklist", @"/Applications/Cydia.app");
    expectAllowed(@"unblacklisted sibling", @"/usr/sbin/sshd");
    expectRestricted(@"blacklisted sibling not whitelisted", @"/usr/sbin/fstab");
    expectAllowed(@"whitelist exact overrides blacklist exact", @"/usr/bin/ssh");
    expectAllowed(@"whitelist mid-filename prefix", @"/usr/sbin/sshd_config");

    // predicate rules (/var paths reach the engine in both modes; /tmp only
    // in rooted — rootless gates on the fixture jbroot, which has no /tmp,
    // exactly like a real rootless device)
    expectRestricted(@"predicate blacklist", @"/var/mobile/jailbreak-files");

    if(!gRootless) {
        expectRestricted(@"predicate blacklist (rooted)", @"/tmp/jailbreak-detector");
    }

    // structure compliance vetoes
    expectRestricted(@"structure veto under /var/mobile", @"/var/mobile/evil/foo");

    if(!gRootless) {
        expectRestricted(@"structure veto at root (rooted)", @"/opt/jb-tool");
    }

    // whitelisted parent, unwhitelisted child (prefix rules match the
    // prefix itself and its direct children — a deeper child is merely
    // unblacklisted, not whitelisted)
    expectAllowed(@"whitelisted Media direct child", @"/var/mobile/Media/DCIM");
    expectAllowed(@"unblacklisted Media grandchild", @"/var/mobile/Media/DCIM/1.jpg");
    expectRestricted(@"blacklist deeper than whitelisted parent", @"/var/mobile/Media/EvilDir/x");

    // restricted roots and recursion
    expectRestricted(@"/var/jb descendant (recursion/fast-path)", @"/var/jb/usr/bin/ssh");
    expectRestricted(@"restricted root /private/preboot", @"/private/preboot/xyz");
    expectRestricted(@"restricted root /cores", @"/cores/crash");

    // /Applications has no existence gate in rooted mode, so the exact
    // blacklist applies; rootless gates on the fixture jbroot (file absent
    // → read allowed), and the C0-1 write probe denies in both modes.
    if(gRootless) {
        expectAllowed(@"exact blacklist, file absent from jbroot", @"/Applications/Evil.app");
    } else {
        expectRestricted(@"exact blacklist outside gates", @"/Applications/Evil.app");
    }

    expectRestrictedWrite(@"write probe: absent blacklisted app denied", @"/Applications/Evil.app");
}

static void testExistenceGates(void) {
    printf("[tests] existence gates + C0-1 write probes\n");

    if(gRootless) {
        // Rootless: /var/jb/usr/lib/libjailbreak.dylib exists in the fixture
        // tree → gate passes → ruleset decides.
        expectRestricted(@"rootless: jbroot file present, ruleset decides", @"/usr/lib/libjailbreak.dylib");
    } else {
        // Rooted: the gate probes the real host /usr/lib, which never holds
        // jailbreak files (irreducible host limitation; see file header).
        expectAllowed(@"rooted: /usr/lib read gate blocks absent host file", @"/usr/lib/libjailbreak.dylib");
    }

    // absent file: read allowed by gate, write denied (C0-1)
    expectAllowed(@"read probe: absent /usr/lib allowed by existence gate", @"/usr/lib/libghost.dylib");
    expectRestrictedWrite(@"write probe: absent /usr/lib denied", @"/usr/lib/libghost.dylib");
}

// Differential-coherence battery. The HookKit hooks cannot run in this Linux
// harness, but every hook funnels its verdict through
// -[Shadow isPathRestricted:options:] / isURLRestricted:options: and the file
// error factory — so this pins the contracts the hooks RELY on, catching a
// regression in one entry point (e.g. a write hook reverting to read intent)
// even without the runtime. Mirrors the engine side of
// docs/HOOK-OUTPUT-AUDIT.md.
static void testDifferentialCoherence(void) {
    printf("[tests] differential coherence (classification/error contracts)\n");

    Shadow* shadow = shdw();
    NSDictionary* write = writeOptions();

    // ---- #8: write-intent agreement across path / URL / default ----
    // Absent restricted exact-rule target: read allowed by the existence gate,
    // but EVERY write form must deny it (C0-1). This is the contract the
    // NSArray/NSDict/NSData write-hook fix now satisfies (they pass write
    // intent); before the fix they used read intent and answered "allowed".
    // libghost.dylib is the canonical restricted-but-absent exact-file target.
    NSString* ghost = @"/usr/lib/libghost.dylib";
    NSURL* ghostURL = [NSURL fileURLWithPath:ghost];

    CHECK(![shadow isPathRestricted:ghost], "absent exact-file: read allowed by existence gate");
    CHECK([shadow isPathRestricted:ghost options:write], "absent exact-file: path write denied");
    CHECK([shadow isURLRestricted:ghostURL options:write], "absent exact-file: URL write denied (NSData/writeToURL contract)");

    // Subtree rules deny regardless of existence in BOTH read and write, so
    // the read/write discrepancy never applies to /var/jb subtrees (rootless).
    if(gRootless) {
        NSString* absentJb = @"/var/jb/usr/lib/definitely-not-there.dylib";
        CHECK([shadow isPathRestricted:absentJb], "rootless /var/jb subtree: read denied when absent");
        CHECK([shadow isPathRestricted:absentJb options:write], "rootless /var/jb subtree: write denied when absent");
    }

    // ---- option-stack coherence ----
    // A stable (allowed) absolute-path verdict is invariant across the option
    // stacks the hooks pass (nil / empty / workingDir-only).
    NSString* allowed = @"/var/mobile/Media/DCIM/1.jpg";
    BOOL base = [shadow isPathRestricted:allowed];

    CHECK(!base, "stable allowed path baseline");
    CHECK([shadow isPathRestricted:allowed options:@{}] == base, "empty options == nil for absolute path");
    CHECK([shadow isPathRestricted:allowed options:@{kShadowRestrictionWorkingDir : @"/"}] == base, "workingDir inert for absolute path");

    // ---- cross-entry-point differential (differential-fuzz) ----
    // The same logical path must yield the SAME verdict through every alias a
    // hook entry point uses: the ObjC string predicate (-isPathRestricted:),
    // the C-string predicate (-isCPathRestricted:), the file-URL predicate
    // (-isURLRestricted:). Any divergence between aliases is a detector-
    // findable consistency break, so a fuzz over vectors asserts they and the
    // expected verdict all agree.
    struct { NSString* path; BOOL restricted; } vectors[] = {
        { @"/var/jb/usr/bin",                            YES },
        { @"/var/mobile/evil/foo",                       YES },
        { @"/var/mobile/Media/DCIM/1.jpg",               NO  },
        { @"/System/Library/Frameworks/UIKit.framework", NO  },
    };

    for(size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        NSString* p = vectors[i].path;
        BOOL viaStr = [shadow isPathRestricted:p];
        BOOL viaC   = [shadow isCPathRestricted:[p UTF8String]];
        BOOL viaURL = [shadow isURLRestricted:[NSURL fileURLWithPath:p]];

        if(viaStr != viaC || viaStr != viaURL || viaStr != vectors[i].restricted) {
            printf("FAIL: differential vector '%s' (str=%d c=%d url=%d expected=%d)\n",
                [p UTF8String], viaStr, viaC, viaURL, vectors[i].restricted);
            gFail++;
        } else {
            gPass++;
        }
    }

    // ---- file-error factory shape (findings #2/#11) ----
    NSError* pathErr = [Shadow fileNoSuchFileErrorForPath:@"/var/x"];
    CHECK([pathErr domain] == NSCocoaErrorDomain && [pathErr code] == NSFileNoSuchFileError, "err domain+code");
    CHECK([pathErr userInfo][NSFilePathErrorKey] != nil, "err carries NSFilePathErrorKey");

    NSURL* u = [NSURL fileURLWithPath:@"/var/x"];
    NSError* urlErr = [Shadow fileNoSuchFileErrorForURL:u];
    CHECK([urlErr code] == NSFileNoSuchFileError, "url err code");
    CHECK([urlErr userInfo][NSURLErrorKey] != nil, "url err carries NSURLErrorKey");
    CHECK([urlErr userInfo][NSFilePathErrorKey] != nil, "url err carries path key too");
}

static void testSchemesAndIDs(void) {
    printf("[tests] schemes, bundle IDs, URLs\n");

    CHECK([shdw() isSchemeRestricted:@"cydia"], "scheme cydia restricted");
    CHECK([shdw() isSchemeRestricted:@"CYDIA"], "scheme case-variant restricted");
    CHECK([shdw() isSchemeRestricted:@"zbra"], "scheme zbra restricted");
    CHECK(![shdw() isSchemeRestricted:@"http"], "scheme http allowed");
    CHECK(![shdw() isSchemeRestricted:@"file"], "scheme file allowed");
    CHECK(![shdw() isSchemeRestricted:@"unknown"], "unknown scheme allowed");
    CHECK(![shdw() isSchemeRestricted:nil], "nil scheme allowed");

    CHECK([shdw() isBundleIDRestricted:@"com.saurik.Cydia"], "bundle ID static list restricted");
    CHECK([shdw() isBundleIDRestricted:@"COM.SAURIK.CYDIA"], "bundle ID case-variant restricted");
    CHECK([shdw() isBundleIDRestricted:@"com.example.tracker"], "bundle ID ruleset restricted");
    CHECK([shdw() isBundleIDRestricted:@"Com.Example.Tracker"], "bundle ID ruleset case-variant restricted");
    CHECK(![shdw() isBundleIDRestricted:@"com.apple.mobilesafari"], "app bundle ID allowed");
    CHECK(![shdw() isBundleIDRestricted:@""], "empty bundle ID allowed");

    CHECK([shdw() isURLRestricted:[NSURL URLWithString:@"cydia://package"]], "URL scheme restricted");
    CHECK(![shdw() isURLRestricted:[NSURL URLWithString:@"http://example.com"]], "URL http allowed");
    CHECK([shdw() isURLRestricted:[NSURL fileURLWithPath:@"/var/jb/usr/bin/ssh"]], "file URL restricted");
}

static void testProtectedNames(void) {
    printf("[tests] protected image names\n");

    CHECK([shdw() isProtectedImagePath:@"/var/jb/usr/lib/libSandy.dylib"], "libSandy protected");
    CHECK([shdw() isProtectedImagePath:@"/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib"], "substrate name protected");
    CHECK([shdw() isProtectedImagePath:@"/usr/lib/libsubstrate.dylib"], "libsubstrate protected");
    CHECK([shdw() isProtectedImagePath:@"/usr/lib/libsubstitute.0.dylib"], "libsubstitute protected");
    CHECK([shdw() isProtectedImagePath:@"/var/jb/usr/lib/shadow.dylib"], "shadow artifact protected");
    CHECK(![shdw() isProtectedImagePath:@"/usr/lib/libsystem_kernel.dylib"], "stock dylib not protected");
    CHECK(![shdw() isProtectedImagePath:@"/System/Library/Frameworks/UIKit.framework"], "stock framework not protected");
    CHECK(![shdw() isProtectedImagePath:nil], "nil path not protected");
}

// Resolve-before-exempt: the harness binary lives in a .app dir, so bundle
// paths are sandbox-exempt; a symlink inside the bundle pointing at a
// restricted target must be caught by the realpath re-check. Runs in both
// modes: rooted resolves to a real host file (staged restricted-target,
// blacklisted by 006-Sandbox.plist); rootless resolves into the fixture
// jbroot tree — the destination must be a REAL path (the kernel resolves
// symlink targets; the virtual filesystem only rewrites access()/realpath()
// inputs), landing in jbrootTarget's prefix range exactly like /var/jb on a
// device.
static void testSandbox(void) {
    printf("[tests] sandbox exemption + resolve-before-exempt\n");

    Shadow* shadow = shdw();
    NSString* evil = [[shadow bundlePath] stringByAppendingPathComponent:@"evil-symlink"];
    NSString* target = gRootless
        ? [[[harnessWorkDir() stringByAppendingPathComponent:@"fs/jb"] stringByAppendingPathComponent:@"usr/sbin"] stringByAppendingPathComponent:@"sshd"]
        : [[harnessWorkDir() stringByAppendingPathComponent:@"shdw-app"] stringByAppendingPathComponent:@"restricted-target"];

    [[NSFileManager defaultManager] createSymbolicLinkAtPath:evil withDestinationPath:target error:nil];

    expectRestricted(@"symlink inside bundle resolving to restricted target", evil);
    expectAllowedOpts(@"noFollow link-location query exempt", evil, @{kShadowRestrictionNoFollow : @YES});
    expectAllowed(@"bundle dir itself exempt", [shadow bundlePath]);
    CHECK([shdw() isURLRestricted:[NSURL fileURLWithPath:evil]], "file URL through bundle symlink");
}

static void testUtilities(void) {
    printf("[tests] utilities\n");

    CHECK([[Shadow getStandardizedPath:@"/usr/bin//ssh"] isEqualToString:@"/usr/bin/ssh"], "standardize double slash");
    CHECK([[Shadow getStandardizedPath:@"/usr/bin/./ssh"] isEqualToString:@"/usr/bin/ssh"], "standardize dot component");
    CHECK([[Shadow getStandardizedPath:@"/usr/bin/ssh/"] isEqualToString:@"/usr/bin/ssh"], "standardize trailing slash");
    CHECK([[Shadow getStandardizedPath:@"/private/var/mobile/x"] isEqualToString:@"/var/mobile/x"], "standardize /private/var");
    CHECK([[Shadow getStandardizedPath:@"/usr/bin/ssh"] isEqualToString:@"/usr/bin/ssh"], "standardize passthrough");

    NSArray* paths = @[@"/usr/bin/ssh", @"/var/mobile/evil/foo", @"/var/mobile/Media/DCIM/1.jpg"];
    NSArray* restricted = [Shadow filterPathArray:paths restricted:YES options:nil];

    CHECK([restricted count] == 1 && [[restricted objectAtIndex:0] isEqualToString:@"/var/mobile/evil/foo"], "filterPathArray restricted");

    NSArray* urls = @[[NSURL fileURLWithPath:@"/var/mobile/evil/foo"], [NSURL fileURLWithPath:@"/var/mobile/Documents/x"]];
    NSArray* restrictedURLs = [Shadow filterPathArray:urls restricted:YES options:nil];

    CHECK([restrictedURLs count] == 1 && [[restrictedURLs objectAtIndex:0] isEqual:[NSURL fileURLWithPath:@"/var/mobile/evil/foo"]], "filterPathArray URLs restricted");

    NSError* err = [Shadow fileNoSuchFileErrorForPath:@"/var/x"];

    CHECK([err domain] == NSCocoaErrorDomain && [err code] == NSFileNoSuchFileError, "file error factory");
}

// Hook entry points the unit groups don't reach directly: the const-char
// path API (libc.x/syscall.x/sandbox.x/dyld.x), the address API
// (objc.x/dyld.x/mem.x/sandbox.x/NSThread.x/NSBundle.x), and the
// dpkg-database generator (shadowd/SystemRules side).
static void testHookEntryPoints(void) {
    printf("[tests] hook entry points\n");

    // isCPathRestricted: const-char variant of the path decision.
    CHECK([shdw() isCPathRestricted:"/Applications/Cydia.app"], "isCPathRestricted restricted");
    CHECK(![shdw() isCPathRestricted:"/var/mobile/Media/DCIM/1.jpg"], "isCPathRestricted allowed");
    CHECK(![shdw() isCPathRestricted:NULL], "isCPathRestricted NULL allowed");

    // isAddrRestricted: the dyld-image stub resolves no image, so both the
    // NULL and non-NULL address paths exercise the method body.
    CHECK(![shdw() isAddrRestricted:NULL], "isAddrRestricted NULL allowed");
    CHECK(![shdw() isAddrRestricted:(const void*)0x1234], "isAddrRestricted unresolvable address allowed");
}

// Pure hook filters (ShadowCore.dylib/hooks/filters.h): the per-record mount
// decision and the APFS snapshot name classifier. Compiled into the harness
// directly — no Darwin-only headers, so the exact device logic is testable.
#include "filters.h"

static void testHookFilters(void) {
    printf("[tests] hook filters (mount + snapshot)\n");

    // shdw_mount_filter: restricted verdict removes the record.
    uint32_t flags = 0;
    CHECK(shdw_mount_filter("/", "/dev/disk1", &flags, 1, 1) == 0, "mount filter: restricted removed");

    // restricted=0 + "/" + statfsFlags=1 -> kept, MNT_RDONLY OR'd in.
    flags = 0;
    CHECK(shdw_mount_filter("/", "/dev/disk1", &flags, 1, 0) == 1, "mount filter: root kept");
    CHECK((flags & MNT_RDONLY) != 0, "mount filter: MNT_RDONLY OR'd for root with statfsFlags");

    // restricted=0 + "/" + statfsFlags=0 -> kept, flags untouched.
    flags = 0;
    CHECK(shdw_mount_filter("/", "/dev/disk1", &flags, 0, 0) == 1, "mount filter: root kept without statfsFlags");
    CHECK(flags == 0, "mount filter: flags untouched without statfsFlags");

    // restricted=0 + non-"/" + statfsFlags=1 -> kept, flags untouched.
    flags = 0;
    CHECK(shdw_mount_filter("/System", "/dev/disk1", &flags, 1, 0) == 1, "mount filter: non-root kept");
    CHECK(flags == 0, "mount filter: non-root flags untouched");

    // NULL mntonname -> kept, no crash.
    CHECK(shdw_mount_filter(NULL, "/dev/disk1", &flags, 1, 0) == 1, "mount filter: NULL mntonname kept");

    // shdw_snapshot_is_jb: exact-match deny-list.
    CHECK(shdw_snapshot_is_jb("fakefs") == 1, "snapshot: fakefs hidden");
    CHECK(shdw_snapshot_is_jb("com.apple.os.update-1234") == 0, "snapshot: stock update kept");
    CHECK(shdw_snapshot_is_jb("random") == 0, "snapshot: random kept");
    CHECK(shdw_snapshot_is_jb(NULL) == 0, "snapshot: NULL kept");
}

// generateDatabase: builds a ruleset dict from the dpkg info database.
// Coverage-gap tests: the branches the unit groups don't reach (from the
// gcov report) — isURLRestricted's nil/reference-URL paths,
// getStandardizedPath's slow-path triggers, the backend's reload gate and
// dir-add detection, and RulesetEngine's cache-restore and exception paths.
static void testCoverageGaps(void) {
    printf("[tests] coverage gaps\n");

    // isURLRestricted: nil branch.
    CHECK(![shdw() isURLRestricted:nil], "isURLRestricted nil allowed");

    // file-reference URL: GNUstep may or may not produce one; if it does,
    // the verdict must match the path verdict.
    NSURL* ref = [[NSURL fileURLWithPath:@"/var/jb/usr/bin/ssh"] fileReferenceURL];

    if(ref) {
        CHECK([shdw() isURLRestricted:ref], "isURLRestricted file-reference URL restricted");
    }

    // getStandardizedPath slow-path triggers: query/fragment markers strip
    // to the path; /private/etc and /var/tmp rewrite.
    CHECK([[Shadow getStandardizedPath:@"/usr/bin/ssh?x=1"] isEqualToString:@"/usr/bin/ssh"], "standardize query marker");
    CHECK([[Shadow getStandardizedPath:@"/usr/bin/ssh#frag"] isEqualToString:@"/usr/bin/ssh"], "standardize fragment marker");
    CHECK([[Shadow getStandardizedPath:@"/private/etc/hosts"] isEqualToString:@"/etc/hosts"], "standardize /private/etc");
    CHECK([[Shadow getStandardizedPath:@"/var/tmp/x"] isEqualToString:@"/tmp/x"], "standardize /var/tmp");
    CHECK([[Shadow getStandardizedPath:@"/./usr/bin/ssh"] isEqualToString:@"/usr/bin/ssh"], "standardize leading dot component");

    // Percent-encoding is non-idempotent on this stack (documented); the
    // first-pass output must still be stable across a second pass.
    NSString* pct = [Shadow getStandardizedPath:@"/usr/bin/%2e/ssh"];

    CHECK([[Shadow getStandardizedPath:pct] isEqualToString:pct], "standardize stable after first pass");

    // Backend reload gate: rapid repeat queries must NOT bump the ruleset
    // generation (the 1s scan gate).
    ShadowBackend* backend = [[Shadow sharedInstance] valueForKey:@"backend"];
    NSUInteger genBefore = [backend rulesetGeneration];

    (void)[shdw() isPathRestricted:@"/usr/sbin/fstab"];
    (void)[shdw() isPathRestricted:@"/usr/sbin/fstab"];
    CHECK([backend rulesetGeneration] == genBefore, "reload gate: no scan on rapid queries");

    // Decision-cache TTL expiry: after the 2s TTL the entry is recomputed
    // (the age>TTL branch) and must yield the same verdict.
    CHECK([shdw() isPathRestricted:@"/var/jb/usr/bin/ssh"], "cache TTL baseline");
    [NSThread sleepForTimeInterval:2.1];
    CHECK([shdw() isPathRestricted:@"/var/jb/usr/bin/ssh"], "cache TTL expiry recomputes same verdict");

    // Tilde expansion branch: a resolvable tilde escapes to the home dir,
    // and the dot-dot collapses onto the restricted root.
    CHECK([shdw() isPathRestricted:@"~/../var/jb/usr/bin/ssh"], "tilde expansion + dot-dot collapse restricted");

    // Dir-add detection: a NEW ruleset file in the dir must be picked up
    // (dir-mtime path of _checkRulesetChanges), bumping the generation.
    // Runs in both modes (the added blacklist targets the fixture-backed
    // dpkg-tool path so the rootless gate passes).
    {
        NSString* rulesetsDir = [harnessWorkDir() stringByAppendingPathComponent:
            (gRootless ? @"jb/Library/Shadow/Rulesets" : @"root/Library/Shadow/Rulesets")];

        NSDictionary* added = @{
            @"RulesetInfo" : @{@"Name" : @"Test Added", @"Author" : @"harness"},
            @"BlacklistExactPaths" : @[@"/usr/sbin/dpkg-tool"]
        };

        [added writeToFile:[rulesetsDir stringByAppendingPathComponent:@"007-Added.plist"] atomically:YES];
        [NSThread sleepForTimeInterval:1.3];

        // A cache-MISS query triggers the scan + reload (a cached path
        // would skip the backend entirely); only then does the gen bump.
        CHECK([shdw() isPathRestricted:@"/usr/sbin/dpkg-tool"], "added ruleset applies");
        CHECK([backend rulesetGeneration] > genBefore, "dir-add reload bumps generation");

        [[NSFileManager defaultManager] removeItemAtPath:[rulesetsDir stringByAppendingPathComponent:@"007-Added.plist"] error:nil];
        [NSThread sleepForTimeInterval:1.3];
    }

    // RulesetEngine cache-restore path: a second load of an unchanged
    // ruleset must restore from the compiled cache and behave identically.
    NSString* rulesetsDir = [harnessWorkDir() stringByAppendingPathComponent:
        (gRootless ? @"jb/Library/Shadow/Rulesets" : @"root/Library/Shadow/Rulesets")];
    NSURL* overridesURL = [NSURL fileURLWithPath:[rulesetsDir stringByAppendingPathComponent:@"002-Overrides.plist"]];

    RulesetEngine* first = [RulesetEngine rulesetWithURL:overridesURL];
    RulesetEngine* second = [RulesetEngine rulesetWithURL:overridesURL];

    CHECK(first != nil && second != nil, "ruleset double-load");
    CHECK([first isPathWhitelisted:@"/usr/bin/ssh"] == [second isPathWhitelisted:@"/usr/bin/ssh"], "ruleset cache restore preserves semantics");

    // Exception path: a ruleset whose predicate fails to parse is loaded
    // with that rule SKIPPED (per-predicate @try in _compile), never fatal.
    NSURL* badURL = [NSURL fileURLWithPath:[rulesetsDir stringByAppendingPathComponent:@"008-BadPredicate.plist"]];
    RulesetEngine* bad = [RulesetEngine rulesetWithURL:badURL];

    CHECK(bad != nil, "bad-predicate ruleset tolerated");
    CHECK(![bad isPathBlacklisted:@"/var/mobile/bogus-operator-match"], "broken predicate rule skipped");
}

// shadowd ledger battery: the daemon's persistence contract — the wire
// format ("%d|%s|%s|0x%llx|0x%llx", a HARD on-disk constraint) and the
// write-ahead record semantics. The pure format/parse functions run in
// both modes; the file-based functions run in rootless mode where the
// virtual FS maps the ledger dir (/var/jb/var/mobile/...) into the fixture
// tree. The DEBUG self-check constructor in ledger.m also runs at load.
#import "../../shadowd/ledger.h"

static void testShadowdLedger(void) {
    printf("[tests] shadowd ledger\n");

    // Pure wire format + strict parse.
    NSString* literal = @"1|/x|p:1:2|0x3|0x4";

    CHECK([ledger_format_record(1, "/x", "p:1:2", 0x3, 0x4) isEqualToString:literal], "ledger format literal");

    int state = -1;
    NSString* path = nil, *owner = nil;
    uint64_t vnode = 0, vId = 0;

    CHECK(ledger_parse_record(literal, &state, &path, &owner, &vnode, &vId), "ledger parse literal");
    CHECK(state == 1 && [path isEqualToString:@"/x"] && [owner isEqualToString:@"p:1:2"]
        && vnode == 0x3 && vId == 0x4, "ledger parse fields");

    int s2 = -1;
    NSString* p2 = nil, *o2 = nil;
    uint64_t v2 = 0, i2 = 0;

    CHECK(!ledger_parse_record(@"2|/x|o|0x3|0x4", &s2, &p2, &o2, &v2, &i2), "ledger state coercion rejected");
    CHECK(!ledger_parse_record(@"1|/x|o|0x3", &s2, &p2, &o2, &v2, &i2), "ledger short record rejected");
    CHECK(!ledger_parse_record(@"1|/x|o|3|0x4", &s2, &p2, &o2, &v2, &i2), "ledger vnode without 0x rejected");
    CHECK(!ledger_parse_record(@"1|/x|o|0x3|0x4|extra", &s2, &p2, &o2, &v2, &i2), "ledger long record rejected");
    CHECK(ledger_parse_record(@"1|/x||0x3|0x4", &s2, &p2, &o2, &v2, &i2) && [o2 isEqualToString:@""], "ledger empty owner ok");
    CHECK(!ledger_parse_record(@"1|/x|o|y|0x3|0x4", &s2, &p2, &o2, &v2, &i2), "ledger pipe-in-path unrepresentable (rejected)");

    // File semantics (rooted mode: the real container filesystem — the
    // ledger's NSFileManager calls don't go through the virtual FS, which
    // only interposes the libc access/open/realpath). Skips gracefully
    // where /var/mobile is not writable (e.g. macOS CI runners).
    if(!gRootless) {
        gIsRootless = false;
        gBootUUID = @"harness-boot";

        if(!ledger_add_record("/hidden/a", "p:1:1", 0x1234, 0x5678, 1)) {
            printf("  (ledger file tests skipped: ledger dir not writable)\n");
            return;
        }

        NSString* boot = nil;
        NSArray* recs = ledger_read(&boot);

        CHECK([boot isEqualToString:@"harness-boot"] && [recs count] == 1, "ledger read back");
        CHECK([[recs objectAtIndex:0] isEqualToString:@"1|/hidden/a|p:1:1|0x1234|0x5678"], "ledger record content");

        CHECK(ledger_update_record("/hidden/a", "p:1:1", 0x9999, 0x8888, 0), "ledger update");
        recs = ledger_read(&boot);
        CHECK([[recs objectAtIndex:0] isEqualToString:@"0|/hidden/a|p:1:1|0x9999|0x8888"], "ledger update replaces record");

        CHECK(ledger_add_record("/hidden/a", "p:1:2", 0x1111, 0x2222, 1), "ledger second owner");
        CHECK([ledger_read(&boot) count] == 2, "ledger multi-owner");

        CHECK(ledger_remove_owner_record("/hidden/a", "p:1:1"), "ledger remove owner");
        recs = ledger_read(&boot);
        CHECK([recs count] == 1 && [[recs objectAtIndex:0] hasSuffix:@"|p:1:2|0x1111|0x2222"], "ledger other owner intact");

        CHECK(ledger_remove_path_records("/hidden/a"), "ledger remove path");
        CHECK([ledger_read(&boot) count] == 0, "ledger path records gone");

        // Bad header: discarded and the ledger wiped.
        NSString* ledgerPath = @"/var/jb/var/mobile/Library/Preferences/me.jjolano.shadowd/shadowd.ledger";

        [@"GARBAGE\nx\n" writeToFile:ledgerPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        CHECK([ledger_read(&boot) count] == 0, "ledger bad header discarded");
        CHECK(![[NSFileManager defaultManager] fileExistsAtPath:ledgerPath], "ledger bad header wipe removed file");

        gIsRootless = false;
    }
}

// shadowd recovery-decision battery: the daemon's crash-recovery logic
// (the verbatim test double in shadowd/RecoveryHarness.m, drift-guarded by
// verify-recovery-copy.sh) with configurable seams for the kernel-touching
// helpers. Rooted mode only (real files + the real ledger writes).
#import "shadowd/RecoveryHarness.h"

static void testShadowdRecovery(void) {
    printf("[tests] shadowd recovery decisions\n");

    if(gRootless) {
        printf("  (rooted mode only — real files + real ledger writes)\n");
        return;
    }

    NSString* dir = [harnessWorkDir() stringByAppendingPathComponent:@"recov"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString* visible = [dir stringByAppendingPathComponent:@"visible.txt"];
    NSString* gone = [dir stringByAppendingPathComponent:@"gone.txt"];
    [@"x" writeToFile:visible atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[NSFileManager defaultManager] removeItemAtPath:gone error:nil];

    gIsRootless = false;
    gBootUUID = @"harness-boot";

    // WAL writability probe (mirrors testShadowdLedger): the re-hide cases
    // must persist a fresh vnode through ledger_update_record, which needs
    // a writable ledger dir. Skipped gracefully where it isn't (macOS CI).
    bool walOK = ledger_add_record("/recovery-probe", "p:0:0", 0x1, 0x1, 1);
    if(!walOK) {
        printf("  (WAL-dependent re-hide cases skipped: ledger dir not writable)\n");
    }

    // The daemon's allowlist is an exact-path list — records are only
    // admitted for paths the user actually asked to hide.
    NSArray* allow = @[visible, gone, @"/etc/hosts", @"/etc/passwd"];
    NSMutableArray* kept;

    // Malformed → dropped.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record(@"garbage", kept);
    CHECK([kept count] == 0, "recovery: malformed record dropped");

    // Non-allowlisted path → dropped.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record(@"1|/tmp/evil|p:1:1|0x1000|0x2000", kept);
    CHECK([kept count] == 0, "recovery: non-allowlisted path dropped");

    // Implausible saved vnode (A14) → dropped.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    shdw_recovery_set_plausible_range(0x1000, 0xFFFF);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record(@"1|/etc/passwd|p:1:1|0x1|0x2000", kept);
    CHECK([kept count] == 0, "recovery: implausible saved vnode dropped");

    // Existing leased resource → owner added, record kept.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    kept = [NSMutableArray new];
    ShadowResource* res = [ShadowResource resourceWithFd:-1 vnode:0x1000 vId:0x2000 flagSet:YES verified:YES owner:@"p:9:9"];
    [gResources setObject:res forKey:@"/etc/hosts"];
    shdw_test_recover_one_record(@"1|/etc/hosts|p:1:1|0x1000|0x2000", kept);
    CHECK([kept count] == 1, "recovery: leased resource record kept");
    CHECK([res.owners containsObject:@"p:1:1"], "recovery: owner added to leased resource");

    // Visible + mayBeHidden (state 0) → rolled back, no WAL write.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record([NSString stringWithFormat:@"0|%@|p:1:1|0x1000|0x2000", visible], kept);
    CHECK([kept count] == 0, "recovery: mayBeHidden + visible rolled back");

    if(walOK) {
        // Visible + hidden (state 1): re-resolve → fresh-vnode WAL → re-hide.
        shdw_recovery_reset();
        shdw_recovery_set_allowlist(allow);
        shdw_recovery_set_resolve(YES, 0xABCD, 0x1234);
        kept = [NSMutableArray new];
        shdw_test_recover_one_record([NSString stringWithFormat:@"1|%@|p:1:1|0x1000|0x2000", visible], kept);
        NSString* expected = [NSString stringWithFormat:@"1|%@|p:1:1|0xabcd|0x1234", visible];
        CHECK([kept count] == 1, "recovery: visible+hidden re-hidden (record kept)");
        CHECK([[kept objectAtIndex:0] isEqualToString:expected], "recovery: fresh vnode persisted in WAL");
        CHECK([gResources objectForKey:visible] != nil, "recovery: resource re-adopted");
        CHECK([[gResources objectForKey:visible] verified], "recovery: VFLAG_OK verified");

        // Re-resolve failure → record kept for a future retry.
        shdw_recovery_reset();
        shdw_recovery_set_allowlist(allow);
        shdw_recovery_set_resolve(NO, 0, 0);
        kept = [NSMutableArray new];
        NSString* rec1 = [NSString stringWithFormat:@"1|%@|p:1:1|0x1000|0x2000", visible];
        shdw_test_recover_one_record(rec1, kept);
        CHECK([kept count] == 1 && [[kept objectAtIndex:0] isEqualToString:rec1],
            "recovery: re-resolve failure keeps record");

        // VFLAG_FAILED_PRE → fresh-vnode record kept, nothing adopted.
        shdw_recovery_reset();
        shdw_recovery_set_allowlist(allow);
        shdw_recovery_set_resolve(YES, 0xABCD, 0x1234);
        shdw_recovery_set_vflag(1 /* VFLAG_FAILED_PRE */);
        kept = [NSMutableArray new];
        shdw_test_recover_one_record([NSString stringWithFormat:@"1|%@|p:1:1|0x1000|0x2000", visible], kept);
        CHECK([kept count] == 1 && [[kept objectAtIndex:0] isEqualToString:expected],
            "recovery: failed-pre keeps fresh-vnode record");
        CHECK([gResources objectForKey:visible] == nil, "recovery: failed-pre adopts nothing");
    }

    // ENOENT + saved vnode flagged + v_id match → adopted.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    shdw_recovery_set_krw(YES, 0x1000, VISSHADOW, 0x2000);
    kept = [NSMutableArray new];
    NSString* goneRec = [NSString stringWithFormat:@"1|%@|p:1:1|0x1000|0x2000", gone];
    shdw_test_recover_one_record(goneRec, kept);
    CHECK([kept count] == 1, "recovery: ENOENT + flagged adopted");
    CHECK([gResources objectForKey:gone] != nil, "recovery: hidden resource adopted");

    // ENOENT + not flagged → dropped.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    shdw_recovery_set_krw(YES, 0x1000, 0, 0x2000);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record(goneRec, kept);
    CHECK([kept count] == 0, "recovery: un-flagged saved vnode dropped");

    // ENOENT + v_id mismatch → dropped.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    shdw_recovery_set_krw(YES, 0x1000, VISSHADOW, 0x9999);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record(goneRec, kept);
    CHECK([kept count] == 0, "recovery: v_id mismatch dropped");

    // ENOENT + zero saved v_id → refused (flag is set, so only v_id==0 drops it).
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    shdw_recovery_set_krw(YES, 0x1000, VISSHADOW, 0);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record([NSString stringWithFormat:@"1|%@|p:1:1|0x1000|0x0", gone], kept);
    CHECK([kept count] == 0, "recovery: zero saved v_id refused");

    // krw read failure → dropped.
    shdw_recovery_reset();
    shdw_recovery_set_allowlist(allow);
    shdw_recovery_set_krw(NO, 0, 0, 0);
    kept = [NSMutableArray new];
    shdw_test_recover_one_record(goneRec, kept);
    CHECK([kept count] == 0, "recovery: krw read failure dropped");

    ledger_wipe();
}

// Rootless only — the stub maps /Library/dpkg/info into the fixture jbroot
// tree (fixtures/fs/jb/Library/dpkg/info/*.list).
static void testDatabase(void) {
    printf("[tests] dpkg database generation\n");

    if(!gRootless) {
        printf("  (rootless mode only)\n");
        return;
    }

    NSString* dpkgProbe = @"/usr/sbin/dpkg-tool";

    // NOTE: the probe path is deliberately NOT queried before the database
    // ruleset is applied — a pre-reload verdict would sit in the decision
    // cache under the same generation and be served after the reload.
    NSDictionary* db = [Shadow generateDatabase];

    CHECK(db != nil, "generateDatabase produces a ruleset");

    if(db) {
        NSArray* blacklist = [db objectForKey:@"BlacklistExactPaths"];
        NSArray* schemes = [db objectForKey:@"BlacklistURLSchemes"];

        CHECK([blacklist containsObject:@"/usr/bin/sshd"], "db blacklist includes package file paths");
        CHECK([blacklist containsObject:@"/Applications/FakeJB.app"], "db blacklist includes installed apps");
        CHECK([blacklist containsObject:dpkgProbe], "db blacklist includes the dpkg-tool probe");
        CHECK(![blacklist containsObject:@"/usr/bin/ssh"], "db blacklist skips base.list (system files)");
        CHECK(![blacklist containsObject:@"/var/lib/apt/lists"], "db blacklist skips base.list entries");
        CHECK([schemes containsObject:@"fakejb"], "db schemes harvested from installed app bundles");

        // End-to-end: the generated database applied back through the
        // engine (the shadowd flow) — write it as a ruleset, reload, and
        // the dpkg-installed paths become restricted.
        NSString* rulesetsDir = [[harnessWorkDir() stringByAppendingPathComponent:@"jb/Library/Shadow"]
            stringByAppendingPathComponent:@"Rulesets"];

        if([db writeToFile:[rulesetsDir stringByAppendingPathComponent:@"009-Database.plist"] atomically:YES]) {
            [NSThread sleepForTimeInterval:1.3];
            // Fresh cache-miss path triggers the scan + reload.
            (void)[shdw() isPathRestricted:@"/tmp/fresh-trigger"];
            CHECK([shdw() isPathRestricted:dpkgProbe], "generated database ruleset restricts dpkg paths");
        }
    }
}

// Ruleset reload via mtime + generation invalidation + last-known-good.
// Rooted mode only to keep runtime down; logic is mode-independent.
static void testReload(void) {
    printf("[tests] ruleset reload + last-known-good\n");

    if(gRootless) {
        printf("  (rooted mode only)\n");
        return;
    }

    NSString* ruleset = [[harnessWorkDir() stringByAppendingPathComponent:@"root/Library/Shadow/Rulesets"]
        stringByAppendingPathComponent:@"005-Reload.plist"];
    NSString* probe = @"/usr/lib/libreloadtest.dylib";
    NSString* minimal = @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict><key>RulesetInfo</key><dict><key>Name</key><string>Reload</string><key>Author</key><string>harness</string></dict></dict></plist>";

    // staged 005-Reload.plist blacklists the probe path (see below)
    expectRestrictedWrite(@"reload: baseline restricted", probe);

    [minimal writeToFile:ruleset atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [NSThread sleepForTimeInterval:1.3];
    expectAllowedOpts(@"reload: rule removal observed (generation invalidation)", probe, writeOptions());

    [@"not a plist at all {{{" writeToFile:ruleset atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [NSThread sleepForTimeInterval:1.3];
    expectAllowedOpts(@"reload: last-known-good served after malformed rewrite", probe, writeOptions());
    expectRestricted(@"reload: other rulesets unaffected", @"/usr/sbin/fstab");
}

// ---------------------------------------------------------------------------
// Adversary battery (fixture rulesets): probes that try to DODGE the engine
// — normalization attacks, case variants, alias paths, creatable-file
// probes, mode-divergent paths — plus a report-only mutation sweep.
//
// Expectations encode the ENGINE's true semantics per mode (the same code
// runs on device): a deviation from expectation is a LEAK and fails the
// run. An "allowed" expectation is correct engine behavior (e.g. a
// case-variant of a case-sensitive rule points at a file that cannot exist
// on a device), always annotated.
// ---------------------------------------------------------------------------

typedef struct {
    const char* name;
    const char* path;      // query path, or a file:// URL when url=YES
    BOOL url;              // query via isURLRestricted
    BOOL write;            // C0-1 write probe (skips existence gates)
    BOOL expRooted;        // expected verdict in rooted mode
    BOOL expRootless;      // expected verdict in rootless mode
    const char* note;      // why the expectation (esp. allowed cases)
} AdvProbe;

static const AdvProbe kAdvProbes[] = {
    // Normalization attacks: standardization must collapse these onto the
    // restricted canonical path (/var/jb fast-path in rootless; exact
    // blacklist + recursion in rooted).
    { "double slash /var//jb/usr/bin/ssh", "/var//jb/usr/bin/ssh", NO, NO, YES, YES,
      "standardization collapses //" },
    { "dot component /var/jb/./usr/bin/ssh", "/var/jb/./usr/bin/ssh", NO, NO, YES, YES,
      "standardization collapses /./" },
    { "trailing slash /var/jb/usr/bin/ssh/", "/var/jb/usr/bin/ssh/", NO, NO, YES, YES,
      "standardization strips trailing slash" },
    { "dot-dot /var/./jb/../jb/usr/bin/ssh", "/var/./jb/../jb/usr/bin/ssh", NO, NO, YES, YES,
      "standardization collapses dot-dot" },
    { "dot-dot prefix /../var/jb/usr/bin/ssh", "/../var/jb/usr/bin/ssh", NO, NO, YES, YES,
      "standardization collapses leading dot-dot" },
    { "tilde escape ~/../var/jb/usr/bin/ssh", "~/../var/jb/usr/bin/ssh", NO, NO, YES, YES,
      "tilde expands to home, dot-dot collapses onto /var/jb" },
    { "file URL /var/jb/usr/bin/ssh", "file:///var/jb/usr/bin/ssh", YES, NO, YES, YES,
      "file URL takes the path" },
    { "private-var URL file:///private/var/jb/...", "file:///private/var/jb/usr/bin/ssh", YES, NO, YES, YES,
      "/private/var standardizes to /var" },

    // Case variants: only the case-insensitive predicate (SELF LIKE[c]
    // '*/Cydia.app*') covers them; exact/prefix rules are case-sensitive.
    { "case variant /Applications/CYDIA.APP", "/Applications/CYDIA.APP", NO, NO, YES, NO,
      "rooted: LIKE[c] Cydia rule; rootless: existence gate blocks (no such file in jbroot)" },
    { "case variant /usr/sbin/FSTAB", "/usr/sbin/FSTAB", NO, NO, NO, NO,
      "exact blacklist is case-sensitive; no such file exists on a device" },
    { "case variant /var/mobile/JAILBREAK-FILES", "/var/mobile/JAILBREAK-FILES", NO, NO, YES, YES,
      "GNUstep evaluates CONTAINS case-insensitively (Cocoa is case-sensitive: on-device this variant is allowed — documented divergence)" },

    // Mode-divergent paths (fast-path prefix semantics differ).
    { "jbroot sibling /var/jb-backup", "/var/jb-backup", NO, NO, NO, YES,
      "rootless fast-path is a /var/jb string prefix; rooted has no rule for the sibling" },
    { "jbroot sibling child /var/jb2/foo", "/var/jb2/foo", NO, NO, NO, YES,
      "same /var/jb prefix semantics (rootless); nothing there on device (rooted)" },

    // Fast paths and prefixes.
    { "preboot prefix /private/preboot/jb-abc", "/private/preboot/jb-abc", NO, NO, YES, YES,
      "001 prefix rule (rooted) / restricted-root fast path (rootless)" },
    { "cores prefix /cores/crash", "/cores/crash", NO, NO, YES, YES,
      "001 prefix rule (rooted) / restricted-root fast path (rootless)" },

    // Creatable-file probes (C0-1): a detector probing a restricted path it
    // could create must get a denial even though reads are gate-allowed.
    { "write probe /usr/lib/libghost.dylib", "/usr/lib/libghost.dylib", NO, YES, YES, YES,
      "C0-1: write probes skip existence gates in both modes" },

    // False positives: normalization of legit paths must stay allowed.
    { "legit /var/mobile/Media/./DCIM/1.jpg", "/var/mobile/Media/./DCIM/1.jpg", NO, NO, NO, NO,
      "collapses to the whitelisted/unblacklisted Media path" },
    { "legit /var/mobile//Media/DCIM/1.jpg", "/var/mobile//Media/DCIM/1.jpg", NO, NO, NO, NO,
      "collapses to the whitelisted/unblacklisted Media path" },
    { "legit /usr/bin/true", "/usr/bin/true", NO, NO, NO, NO,
      "no rule matches" },
    { "legit /var/mobile/Library/Preferences/x", "/var/mobile/Library/Preferences/x", NO, NO, NO, NO,
      "no rule matches" },
};

static void runAdversary(void) {
    printf("[adversary] evasion battery (rootless=%d)\n", gRootless);

    for(NSUInteger i = 0; i < sizeof(kAdvProbes) / sizeof(kAdvProbes[0]); i++) {
        AdvProbe p = kAdvProbes[i];
        NSString* path = [NSString stringWithUTF8String:p.path];
        BOOL got;
        BOOL expected = gRootless ? p.expRootless : p.expRooted;

        if(p.url) {
            got = [shdw() isURLRestricted:[NSURL URLWithString:path]];
        } else if(p.write) {
            got = [shdw() isPathRestricted:path options:writeOptions()];
        } else {
            got = [shdw() isPathRestricted:path];
        }

        if(got == expected) {
            gPass++;
            printf("  %-42s → %s\n", p.name, got ? "RESTRICTED" : "allowed");
        } else {
            gFail++;
            printf("LEAK: %s (expected %s, got %s) — %s\n", p.name,
                expected ? "restricted" : "allowed",
                got ? "restricted" : "allowed", p.note);
        }
    }

    // Report-only mutation sweep: every mangled probe, classified. No hard
    // assertions — verdicts are rule-dependent; the classification is the
    // point (a detector that can dodge a rule via normalization is visible
    // here as "allowed").
    const char* bases[] = {
        "/Applications/Cydia.app",
        "/var/jb/usr/bin/ssh",
        "/usr/sbin/fstab",
        "/var/mobile/evil/foo",
    };

    printf("[adversary] mutation sweep (report only)\n");

    for(NSUInteger i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
        NSString* base = [NSString stringWithUTF8String:bases[i]];
        NSString* last = [base lastPathComponent];
        NSString* parent = [base stringByDeletingLastPathComponent];
        NSString* upperLast = [last uppercaseString];
        NSString* upperAll = [base uppercaseString];

        NSString* mutants[] = {
            [parent stringByAppendingPathComponent:upperLast],                 // last-component case
            upperAll,                                                          // full case
            [base stringByReplacingOccurrencesOfString:@"/" withString:@"//"], // double slashes
            [base stringByAppendingString:@"/"],                               // trailing slash
            [@"/.." stringByAppendingString:base],                             // dot-dot prefix
            [@"~/.." stringByAppendingString:base],                            // tilde escape
        };
        const char* labels[] = { "case-last", "case-all", "//-dup", "trail-/", "..-prefix", "~-escape" };

        for(NSUInteger m = 0; m < sizeof(mutants) / sizeof(mutants[0]); m++) {
            BOOL got = [shdw() isPathRestricted:mutants[m]];
            printf("  %-12s %-30s → %s\n", labels[m], [mutants[m] UTF8String],
                got ? "RESTRICTED" : "allowed");
        }
    }
}

// ---------------------------------------------------------------------------
// Benign-app battery: a normal, detector-free app must be UNAFFECTED by
// Shadow. Every operation below runs twice — shadow filter OFF (baseline)
// and ON — and each outcome (success/failure AND errno) must be identical.
// Any divergence means a hook changes standard app behavior = FAIL.
// ---------------------------------------------------------------------------

typedef struct {
    const char* name;
    BOOL (^op)(int*);        // returns YES on success; sets errno
} BenignOp;

#define B_ACCESS(_path, _mode) ^BOOL(int* e) { \
    errno = 0; \
    int r = access(_path, _mode); \
    *e = errno; \
    return r == 0; \
}

#define B_OPENREAD(_path, _expect) ^BOOL(int* e) { \
    errno = 0; \
    int fd = open(_path, O_RDONLY); \
    if(fd < 0) { *e = errno; return NO; } \
    char buf[64]; \
    ssize_t n = read(fd, buf, sizeof(buf) - 1); \
    close(fd); \
    buf[n > 0 ? n : 0] = '\0'; \
    *e = 0; \
    return n > 0 && strncmp(buf, _expect, strlen(_expect)) == 0; \
}

#define B_WRITEUNLINK(_dir) ^BOOL(int* e) { \
    errno = 0; \
    char path[PATH_MAX]; \
    snprintf(path, sizeof(path), "%s/scratch-%d", _dir, getpid()); \
    int fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0644); \
    if(fd < 0) { *e = errno; return NO; } \
    if(write(fd, "x", 1) != 1) { *e = errno; close(fd); return NO; } \
    close(fd); \
    unlink(path); \
    *e = 0; \
    return YES; \
}

#define B_STAT(_path) ^BOOL(int* e) { \
    errno = 0; \
    NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:_path error:nil]; \
    *e = errno; \
    return attrs != nil; \
}

#define B_LISTDIR(_dir, _entry) ^BOOL(int* e) { \
    errno = 0; \
    NSArray* items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:_dir error:nil]; \
    *e = errno; \
    return [items containsObject:_entry]; \
}

#define B_SCHEME(_scheme, _wantRestricted) ^BOOL(int* e) { \
    *e = 0; \
    return [shdw() isSchemeRestricted:_scheme] == _wantRestricted; \
}

#define B_BUNDLEID(_bid, _wantRestricted) ^BOOL(int* e) { \
    *e = 0; \
    return [shdw() isBundleIDRestricted:_bid] == _wantRestricted; \
}

#define B_PROTECTED(_path, _wantProtected) ^BOOL(int* e) { \
    *e = 0; \
    return [shdw() isProtectedImagePath:_path] == _wantProtected; \
}

static void runBenignBattery(void) {
#if !defined(__linux__)
    printf("[benign] skipped: shadow filter is Linux-only\n");
    return;
#else
    printf("[benign] normal app session, filter OFF vs ON (rootless)\n");

    NSString* container = [harnessWorkDir() stringByAppendingPathComponent:@"app-container"];    NSString* docs = [container stringByAppendingPathComponent:@"Documents"];
    NSString* prefs = [container stringByAppendingPathComponent:@"Library/Preferences"];
    NSString* tmp = [container stringByAppendingPathComponent:@"tmp"];

    BenignOp ops[] = {
        { "read own document", B_OPENREAD([[docs stringByAppendingPathComponent:@"notes.txt"] UTF8String], "hello from the app") },
        { "stat own document", B_STAT([docs stringByAppendingPathComponent:@"notes.txt"]) },
        { "list own Documents", B_LISTDIR(docs, @"notes.txt") },
        { "write+unlink own tmp file", B_WRITEUNLINK([tmp UTF8String]) },
        { "access own prefs (R_OK)", B_ACCESS([[prefs stringByAppendingPathComponent:@"com.example.app.plist"] UTF8String], R_OK) },
        { "access own dir (W_OK)", B_ACCESS([tmp UTF8String], W_OK) },
        { "own file named like JB artifact (ssh)", B_ACCESS([[container stringByAppendingPathComponent:@"ssh"] UTF8String], F_OK) },
        { "absent own file → ENOENT preserved", B_ACCESS([[prefs stringByAppendingPathComponent:@"missing.plist"] UTF8String], F_OK) },
        { "scheme http not restricted", B_SCHEME(@"http", NO) },
        { "scheme cydia restricted (Shadow holds)", B_SCHEME(@"cydia", YES) },
        { "stock bundle ID not restricted", B_BUNDLEID(@"com.apple.mobilesafari", NO) },
        { "stock framework not protected", B_PROTECTED(@"/System/Library/Frameworks/UIKit.framework", NO) },
        { "stock dylib not protected", B_PROTECTED(@"/usr/lib/libsystem_kernel.dylib", NO) },
    };

    NSUInteger count = sizeof(ops) / sizeof(ops[0]);
    BOOL base[32];
    int baseErrno[32];

    // Pass 1: baseline — shadow filter OFF.
    for(NSUInteger i = 0; i < count; i++) {
        base[i] = ops[i].op(&baseErrno[i]);
    }

    // Pass 2: shadow filter ON — the hook layer's filtering is active.
    shdw_shadow_filter_set_enabled(1);

    for(NSUInteger i = 0; i < count; i++) {
        int e = 0;
        BOOL got = ops[i].op(&e);

        if(got == base[i] && (!got || e == baseErrno[i])) {
            gPass++;
            printf("  %-44s → %s%s\n", ops[i].name, got ? "ok" : "ENOENT-like",
                !got ? " (unchanged)" : "");
        } else {
            gFail++;
            printf("AFFECTED: %s — baseline %s (errno %d), shadow %s (errno %d)\n",
                ops[i].name, base[i] ? "ok" : "failed", baseErrno[i],
                got ? "ok" : "failed", e);
        }
    }

    shdw_shadow_filter_set_enabled(0);
#endif
}

#import "detectors/ShadowDetector.h"

// ---------------------------------------------------------------------------
// Shipped-ruleset battery: the PRODUCT rulesets (StandardRules +
// JailbreakMisc) are only exercised by the detector battery's shadow pass.
// This battery runs the classic detector-path assertions plus the whitelist/
// structure/prefix semantics directly against the shipped rulesets, in both
// modes (the rootless gates via the virtual FS, the rooted via C0-1 write
// probes where the host /usr/lib gate would interfere).
// ---------------------------------------------------------------------------

typedef struct {
    const char* path;
    BOOL write;          // C0-1 write probe (rooted /usr/lib lanes)
    BOOL rootedExp;
    BOOL rootlessExp;
    const char* note;
} ShippedProbe;

static const ShippedProbe kShippedProbes[] = {
    { "/var/jb", NO, YES, YES, "JailbreakMisc /var/jb prefix (rootless fast-path)" },
    { "/var/jb/usr/bin/ssh", NO, YES, YES, "/var/jb prefix + recursion" },
    { "/usr/sbin/sshd", NO, YES, YES, "exact (added by the ruleset audit)" },
    { "/usr/bin/ssh", NO, YES, YES, "exact (added by the ruleset audit)" },
    { "/bin/bash", NO, YES, YES, "exact (added by the ruleset audit)" },
    { "/etc/ssh/sshd_config", NO, YES, YES, "exact (added by the ruleset audit)" },
    { "/usr/bin/sftp", NO, YES, YES, "exact (added by the ruleset audit)" },
    { "/Applications/Cydia.app", NO, YES, YES, "LIKE[c] '*/Cydia.app*' predicate" },
    { "/Applications/CYDIA.APP", NO, NO, NO, "shipped Cydia predicate is case-sensitive; the case-variant file doesn't exist on any device (real file is lowercase) — allowed is correct" },
    { "/Applications/Dopamine.app", NO, YES, YES, "LIKE[c] '*/Dopamine.app*' predicate" },
    { "/Library/MobileSubstrate/MobileSubstrate.dylib", NO, YES, YES, "MobileSubstrate prefix" },
    { "/cores/crash", NO, YES, YES, "/cores prefix (rootless fast-path)" },
    { "/private/preboot/jb-abc", NO, YES, YES, "jb- prefix + LIKE /private/preboot/*/jb*" },
    { "/jb", NO, YES, YES, "exact" },
    { "/var/binpack", NO, YES, YES, "binpack prefix" },
    { "/usr/lib/libjailbreak.dylib", NO, NO, YES, "exact (rooted read is host-gated: use write probe)" },
    { "/usr/lib/libjailbreak.dylib", YES, YES, YES, "C0-1 write probe (rooted)" },
    { "/usr/lib/TweakInject", YES, YES, YES, "prefix, write probe (rooted)" },
    { "/tmp/randomfile", NO, YES, NO, "/tmp/ prefix (rootless: gate blocks non-jbroot reads)" },
    { "/tmp/com.apple.installer", NO, YES, NO, "whitelist /tmp/com.apple defeated by parent recursion — documented" },
    { "/var/root/.ssh/authorized_keys", NO, YES, YES, "/var/root/ prefix" },
    { "/opt/jb", NO, YES, YES, "structure veto: opt not in '/' set (rootless gate passes via fixture file)" },
    { "/var/mobile/evil", NO, YES, YES, "structure veto: evil not in /var/mobile set" },
    { "/var/mobile/Library/Preferences/com.apple.springboard.plist", NO, YES, YES, "compliance veto: plist not in the Preferences children set (whitelist can't rescue)" },
    { "/var/mobile/Media/DCIM/1.jpg", NO, NO, NO, "structure-compliant, unblacklisted" },
    { "/var/mobile/Documents/notes.txt", NO, NO, NO, "structure-compliant, unblacklisted" },
    { "/var/containers/Bundle/Application/ABCDEF/App.app", NO, NO, NO, "app container, structure-compliant" },
    { "/usr/lib/libsystem_kernel.dylib", YES, NO, NO, "stock dylib unblacklisted (write probe)" },
};

static void testShippedRulesets(void) {
    printf("[shipped] product rulesets (rootless=%d)\n", gRootless);

    for(NSUInteger i = 0; i < sizeof(kShippedProbes) / sizeof(kShippedProbes[0]); i++) {
        ShippedProbe p = kShippedProbes[i];
        NSString* path = [NSString stringWithUTF8String:p.path];
        BOOL expected = gRootless ? p.rootlessExp : p.rootedExp;
        BOOL got = p.write
            ? [shdw() isPathRestricted:path options:writeOptions()]
            : [shdw() isPathRestricted:path];

        if(got == expected) {
            gPass++;
        } else {
            gFail++;
            printf("FAIL: shipped %s — expected %s, got %s (%s)\n",
                p.path, expected ? "restricted" : "allowed",
                got ? "restricted" : "allowed", p.note);
        }
    }

    // Schemes and bundle IDs per the shipped rulesets.
    CHECK([shdw() isSchemeRestricted:@"cydia"], "shipped scheme cydia restricted");
    CHECK([shdw() isSchemeRestricted:@"undecimus"], "shipped scheme undecimus restricted");
    CHECK(![shdw() isSchemeRestricted:@"http"], "shipped scheme http allowed");
    CHECK([shdw() isBundleIDRestricted:@"com.saurik.Cydia"], "shipped bundle id restricted");
    CHECK(![shdw() isBundleIDRestricted:@"com.apple.mobilesafari"], "shipped app bundle id allowed");
}

// ---------------------------------------------------------------------------
// Detector battery (real detector vs Shadow on/off, rootless virtual FS)
// ---------------------------------------------------------------------------

// Moves every ruleset plist aside (or back), then sleeps past the engine's
// 1s change-scan gate so the next engine query reloads. Linux-only (used by
// the virtual-FS detector battery).
#if defined(__linux__)
static void setRulesetsEnabled(BOOL enabled, NSString* rulesetsDir) {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSArray* items = [fm contentsOfDirectoryAtPath:rulesetsDir error:nil];

    for(NSString* item in items) {
        if(enabled) {
            if(![item hasSuffix:@".plist.off"]) {
                continue;
            }

            NSString* dst = [item substringToIndex:[item length] - 4]; // strip ".off"
            [fm moveItemAtPath:[rulesetsDir stringByAppendingPathComponent:item]
                        toPath:[rulesetsDir stringByAppendingPathComponent:dst]
                         error:nil];
        } else if([[item pathExtension] isEqualToString:@"plist"]) {
            [fm moveItemAtPath:[rulesetsDir stringByAppendingPathComponent:item]
                        toPath:[rulesetsDir stringByAppendingPathComponent:[item stringByAppendingString:@".off"]]
                         error:nil];
        }
    }

    [NSThread sleepForTimeInterval:1.3];
}
#endif // __linux__

// Runs the ported detector twice against the engine:
//   raw pass    — Shadow OFF (rulesets emptied, filter disabled): the
//                 detector must find the simulated jailbreak.
//   shadow pass — Shadow ON (shipped rulesets restored, filter enabled):
//                 the engine must hide everything the detector probes.
static void runDetectorBattery(void) {
#if !defined(__linux__)
    printf("[detector] skipped: virtual-FS interposition is Linux-only\n");
    return;
#else
    NSString* rulesetsDir = [[harnessWorkDir() stringByAppendingPathComponent:@"jb/Library/Shadow"]
        stringByAppendingPathComponent:@"Rulesets"];

    printf("[detector] IOSSecuritySuite-style detector vs Shadow (rootless)\n");

    // RAW: Shadow off.
    setRulesetsEnabled(NO, rulesetsDir);
    shdw_shadow_filter_set_enabled(0);

    NSArray* rawAudit = ShdwDetectorAudit();
    NSUInteger rawFired = 0;

    for(NSDictionary* entry in rawAudit) {
        if([[entry objectForKey:@"fired"] boolValue]) {
            rawFired++;
            printf("  raw hit: %s\n", [[entry objectForKey:@"probe"] UTF8String]);
        }
    }

    printf("  raw (no Shadow)      → %s (%lu probes fired)\n",
        rawFired > 0 ? "JAILBROKEN" : "clean", (unsigned long)rawFired);

    CHECK(rawFired > 0, "detector detects the simulated jailbreak without Shadow");

    // SHADOW: rulesets restored + filter on. Every fired probe is a LEAK —
    // a ruleset gap the detector can see through.
    setRulesetsEnabled(YES, rulesetsDir);
    shdw_shadow_filter_set_enabled(1);

    NSArray* shadowAudit = ShdwDetectorAudit();
    NSUInteger leaks = 0;

    for(NSDictionary* entry in shadowAudit) {
        if([[entry objectForKey:@"fired"] boolValue]) {
            leaks++;
            gFail++;
            printf("LEAK: %s\n", [[entry objectForKey:@"probe"] UTF8String]);
        }
    }

    if(leaks == 0) {
        gPass++;
        printf("  shadow (Shadow on)   → clean (%lu probes, all hidden)\n",
            (unsigned long)[shadowAudit count]);
    } else {
        printf("  shadow (Shadow on)   → %lu leaks of %lu probes\n",
            (unsigned long)leaks, (unsigned long)[shadowAudit count]);
    }
#endif
}

// ---------------------------------------------------------------------------
// Detector-probe battery (real shipped rulesets)
// ---------------------------------------------------------------------------

typedef struct {
    const char* name;
    const char* path;
    BOOL write;   // C0-1 write probe (skips existence gates; the only way
                  // /usr/lib probes get device-accurate verdicts on a host)
} Probe;

static const Probe kProbes[] = {
    { "fopen /Applications/Cydia.app", "/Applications/Cydia.app", NO },
    { "access /var/jb/Applications/Cydia.app", "/var/jb/Applications/Cydia.app", NO },
    { "access /var/jb/usr/bin/ssh", "/var/jb/usr/bin/ssh", NO },
    { "access /cores/crash.dump", "/cores/crash.dump", NO },
    { "access /private/preboot/jb-abc", "/private/preboot/jb-abc", NO },
    { "access /private/preboot/jb-abc/usr/bin/sshd", "/private/preboot/jb-abc/usr/bin/sshd", NO },
    { "dlopen /usr/lib/libsubstrate.dylib", "/usr/lib/libsubstrate.dylib", YES },
    { "dlopen /usr/lib/libsubstitute.0.dylib", "/usr/lib/libsubstitute.0.dylib", YES },
    { "dlopen /usr/lib/libjailbreak.dylib", "/usr/lib/libjailbreak.dylib", YES },
    { "dlopen /usr/lib/libsystem_kernel.dylib", "/usr/lib/libsystem_kernel.dylib", YES },
    { "fopen /tmp/randomfile", "/tmp/randomfile", NO },
    { "fopen /tmp/com.apple.installer", "/tmp/com.apple.installer", NO },
    { "access /var/root/.ssh/authorized_keys", "/var/root/.ssh/authorized_keys", NO },
    { "fopen /var/mobile/Documents/notes.txt", "/var/mobile/Documents/notes.txt", NO },
    { "access /var/mobile/evil", "/var/mobile/evil", NO },
    { "access /opt/jb/optool", "/opt/jb/optool", NO },
    { "fopen /var/containers/Bundle/Application/ABCDEF/App.app/App", "/var/containers/Bundle/Application/ABCDEF/App.app/App", NO },
    { "access /Library/MobileSubstrate/MobileSubstrate.dylib", "/Library/MobileSubstrate/MobileSubstrate.dylib", NO },
};

static void runDetect(void) {
    printf("[detect] probe battery against shipped rulesets (rootless=%d)\n", gRootless);

    for(NSUInteger i = 0; i < sizeof(kProbes) / sizeof(kProbes[0]); i++) {
        Probe p = kProbes[i];
        NSString* path = [NSString stringWithUTF8String:p.path];
        BOOL got = p.write
            ? [shdw() isPathRestricted:path options:writeOptions()]
            : [shdw() isPathRestricted:path];

        printf("  %-52s → %s\n", p.name, got ? "RESTRICTED" : "allowed");
    }

    // schemes / bundle IDs / protected names
    printf("  %-52s → %s\n", "openURL cydia://", [shdw() isSchemeRestricted:@"cydia"] ? "RESTRICTED" : "allowed");
    printf("  %-52s → %s\n", "openURL Cydia:// (case variant)", [shdw() isSchemeRestricted:@"Cydia"] ? "RESTRICTED" : "allowed");
    printf("  %-52s → %s\n", "openURL http://", [shdw() isSchemeRestricted:@"http"] ? "RESTRICTED" : "allowed");
    printf("  %-52s → %s\n", "LSApplicationWorkspace com.saurik.Cydia", [shdw() isBundleIDRestricted:@"com.saurik.Cydia"] ? "RESTRICTED" : "allowed");
    printf("  %-52s → %s\n", "LSApplicationWorkspace COM.SAURIK.CYDIA", [shdw() isBundleIDRestricted:@"COM.SAURIK.CYDIA"] ? "RESTRICTED" : "allowed");
    printf("  %-52s → %s\n", "LSApplicationWorkspace com.apple.mobilesafari", [shdw() isBundleIDRestricted:@"com.apple.mobilesafari"] ? "RESTRICTED" : "allowed");
    printf("  %-52s → %s\n", "image name /usr/lib/libSandy.dylib", [shdw() isProtectedImagePath:@"/usr/lib/libSandy.dylib"] ? "RESTRICTED" : "allowed");
    printf("  %-52s → %s\n", "image name /System/Library/Frameworks/UIKit.framework", [shdw() isProtectedImagePath:@"/System/Library/Frameworks/UIKit.framework"] ? "RESTRICTED" : "allowed");
}

// ---------------------------------------------------------------------------

int main(int argc, const char** argv) {
    @autoreleasepool {
        for(int i = 1; i < argc; i++) {
            if(strcmp(argv[i], "--rootless") == 0) {
                gRootless = YES;
            } else if(strcmp(argv[i], "--detect") == 0) {
                gDetect = YES;
            } else if(strcmp(argv[i], "--adversary") == 0) {
                gAdversary = YES;
            } else if(strcmp(argv[i], "--detector") == 0) {
                gDetector = YES;
            } else if(strcmp(argv[i], "--benign") == 0) {
                gBenign = YES;
            } else if(strcmp(argv[i], "--shipped") == 0) {
                gShipped = YES;
            } else if(strcmp(argv[i], "--fuzz") == 0) {
                gFuzz = YES;
            } else if(strcmp(argv[i], "--afuzz") == 0) {
                gAFuzz = YES;
            }
        }

        // The detector/benign/adversarial-fuzz batteries simulate a
        // rootless jailbreak (virtual FS + shadow filter).
        if(gDetector || gBenign || gAFuzz) {
            gRootless = YES;
        }

        if(!getenv("SHADW_HARNESS_STAGED")) {
            // Parent: run every requested mode as a fresh process (fresh
            // singleton/backend per mode). fork+waitpid: stageAndExec
            // execv's (which never returns), so each mode must run in its
            // own child; forked children also get distinct pids, keeping
            // work-dir names collision-free.
            int rc = 0;
            const char* modes[][1] = { {"--rootless"}, {"--rooted"} };
            int modeCount = (!gRootless && (argc == 1 || gFuzz || gShipped)) ? 2 : 1;

            for(int i = 0; i < modeCount; i++) {
                char* argv2[5];
                argv2[0] = (char*)argv[0];
                argv2[1] = modeCount == 2 ? (char*)modes[i][0] : (char*)(gRootless ? "--rootless" : "--rooted");

                if(gDetect) {
                    argv2[2] = (char*)"--detect";
                    argv2[3] = NULL;
                } else if(gAdversary) {
                    argv2[2] = (char*)"--adversary";
                    argv2[3] = NULL;
                } else if(gDetector) {
                    argv2[2] = (char*)"--detector";
                    argv2[3] = NULL;
                } else if(gBenign) {
                    argv2[2] = (char*)"--benign";
                    argv2[3] = NULL;
                } else if(gFuzz) {
                    argv2[2] = (char*)"--fuzz";
                    argv2[3] = NULL;
                } else if(gAFuzz) {
                    argv2[2] = (char*)"--afuzz";
                    argv2[3] = NULL;
                } else {
                    argv2[2] = NULL;
                }

                pid_t pid = fork();

                if(pid == 0) {
                    exit(stageAndExec(3, (const char**)argv2));
                }

                int status = 0;
                waitpid(pid, &status, 0);
                rc |= WEXITSTATUS(status);
            }

            return rc;
        }

        // Child: staged, one mode.
        NSString* work = harnessWorkDir();
        NSString* jbPath = gRootless ? [work stringByAppendingPathComponent:@"fs/jb"] : nil;
        NSString* rulesetsDir = [work stringByAppendingPathComponent:
            (gRootless ? @"jb/Library/Shadow/Rulesets" : @"root/Library/Shadow/Rulesets")];

        // Order matters: the engine reads argv via _NSGetArgv at first
        // sharedInstance init (provided by fsinterpose.c), and the virtual
        // filesystem must be armed before any gate call.
        shdw_fs_set_argv((char**)argv);
        shdw_fs_set_jbroot([jbPath UTF8String]);
        [RootBridge shdwHarnessSetJBPath:jbPath rulesetsDir:rulesetsDir];

        printf("=== Shadow harness (%s, %s) work=%s\n",
            gRootless ? "rootless" : "rooted",
            gDetect ? "detect" : (gAdversary ? "adversary" : (gDetector ? "detector" : (gBenign ? "benign" : (gShipped ? "shipped" : (gFuzz ? "fuzz" : (gAFuzz ? "afuzz" : "unit tests")))))),
            [work UTF8String]);

        if(gDetect) {
            runDetect();
            return 0;
        }

        if(gAdversary) {
            runAdversary();
            printf("=== %d passed, %d failed\n", gPass, gFail);
            return gFail ? 1 : 0;
        }

        if(gDetector) {
            runDetectorBattery();
            printf("=== %d passed, %d failed\n", gPass, gFail);
            return gFail ? 1 : 0;
        }

        if(gBenign) {
            runBenignBattery();
            printf("=== %d passed, %d failed\n", gPass, gFail);
            return gFail ? 1 : 0;
        }

        if(gShipped) {
            testShippedRulesets();
            printf("=== %d passed, %d failed\n", gPass, gFail);
            return gFail ? 1 : 0;
        }

        if(gFuzz) {
            NSUInteger iters = 20000;
            unsigned seed = 0;

            if(getenv("SHADW_FUZZ_ITERS")) {
                iters = (NSUInteger)strtoul(getenv("SHADW_FUZZ_ITERS"), NULL, 10);
            }

            if(getenv("SHADW_FUZZ_SEED")) {
                seed = (unsigned)strtoul(getenv("SHADW_FUZZ_SEED"), NULL, 10);
            }

            return shdw_fuzz_run(iters, seed);
        }

        if(gAFuzz) {
            NSUInteger variants = 2000;
            unsigned seed = 0;

            if(getenv("SHADW_AFUZZ_ITERS")) {
                variants = (NSUInteger)strtoul(getenv("SHADW_AFUZZ_ITERS"), NULL, 10);
            }

            if(getenv("SHADW_AFUZZ_SEED")) {
                seed = (unsigned)strtoul(getenv("SHADW_AFUZZ_SEED"), NULL, 10);
            }

            return shdw_afuzz_run(variants, seed);
        }

        // testReload is rooted-mode only: the ruleset-mutation timing is
        // mode-independent, so one run keeps the sleeps (3s) out of the
        // rootless pass.
        testBasics();
        testRulesets();
        testExistenceGates();
        testDifferentialCoherence();
        testSchemesAndIDs();
        testProtectedNames();
        testSandbox();
        testUtilities();
        testHookEntryPoints();
        testHookFilters();
        testDatabase();
        testCoverageGaps();
        testShadowdLedger();
        testShadowdRecovery();

        if(!gRootless) {
            testReload();
        }

        printf("=== %d passed, %d failed\n", gPass, gFail);
        return gFail ? 1 : 0;
    }
}
