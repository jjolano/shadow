#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/dyld_images.h>
#import <dlfcn.h>
#import <stdatomic.h>

// dyldprobe — on-device verification probe for Shadow.
// Shows the jailbreak the way detectors see it, from four angles:
//   1. dyld_all_image_infos read DIRECTLY from memory (W2's target)
//   2. the dyld API view (_dyld_image_count / _dyld_get_image_name)
//   3. file-existence probes of known jailbreak paths
//   4. URL scheme probes (canOpenURL)
// Plus W2-specific checks appended as sections 5-7: dladdr on addresses
// taken from the direct infoArray read + independent dlsym probes of hidden
// images' symbols, add/remove-image stress against the direct infoArray
// read using a dedicated unloadable on-disk dylib (with a concurrent direct-
// memory reader thread), and uuid / infoArrayChangeTimestamp invariants.
// Run it with Shadow disabled for this app (baseline), then with Shadow
// enabled and all hooks on — the two reports are the test.

// Section 8 helpers: the fishhook rebinding shape IOSSecuritySuite's
// denyFishHook uses, and the dummy replacement it points "dladdr" at.
// A successful revert makes every later dladdr call hit this dummy's 0
// ("no info"), which is exactly what the section detects.
struct rebinding {
    char* name;
    void* replacement;
    void** replaced;
};

static int dyldprobe_dummy_dladdr(const void* addr, Dl_info* info) {
    return 0;
}

// Forward decl: section 8 probes ProbeReport's own address.
static NSString* ProbeReport(void);

static BOOL probe_is_foreign_image(NSString* p, NSString* appPath) {
    return ![p hasPrefix:@"/System"] && ![p hasPrefix:appPath];
}

static void probe_section_1(NSMutableString* out, NSString* appPath) {
    [out appendString:@"== 1. dyld_all_image_infos (direct memory read) ==\n"];
    struct dyld_all_image_infos* infos = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");

    if(infos && infos->infoArray) {
        [out appendFormat:@"infoArrayCount = %lu\n", (unsigned long)infos->infoArrayCount];
        [out appendFormat:@"uuidArrayCount = %lu\n", (unsigned long)infos->uuidArrayCount];
        [out appendString:@"non-system entries:\n"];

        for(uint32_t i = 0; i < infos->infoArrayCount; i++) {
            struct dyld_image_info info = infos->infoArray[i];
            NSString* p = info.imageFilePath ? @(info.imageFilePath) : @"?";

            if(!probe_is_foreign_image(p, appPath)) {
                [out appendFormat:@"  %@\n", p];
            }
        }
    } else {
        [out appendString:@"  (dyld_all_image_infos unavailable)\n"];
    }
}

static void probe_section_2(NSMutableString* out, NSString* appPath) {
    [out appendString:@"\n== 2. dyld API view ==\n"];
    uint32_t count = _dyld_image_count();
    [out appendFormat:@"_dyld_image_count = %u\n", count];

    for(uint32_t i = 0; i < count; i++) {
        const char* n = _dyld_get_image_name(i);
        NSString* p = n ? @(n) : @"?";

        if(!probe_is_foreign_image(p, appPath)) {
            [out appendFormat:@"  %@\n", p];
        }
    }
}

static void probe_section_3(NSMutableString* out, NSFileManager* fm) {
    [out appendString:@"\n== 3. jailbreak path probes (fileExistsAtPath) ==\n"];
    NSArray* jbPaths = @[
        @"/var/jb",
        @"/var/jb/usr/lib/libhooker.dylib",
        @"/var/jb/usr/lib/libsubstitute.0.dylib",
        @"/var/jb/usr/lib/libellekit.dylib",
        @"/var/jb/Library/MobileSubstrate/DynamicLibraries",
        @"/var/jb/bin/sbreload",
        @"/usr/lib/libhooker.dylib",
        @"/usr/lib/libsubstitute.0.dylib",
        @"/usr/lib/libsubstrate.dylib",
        @"/usr/lib/libellekit.dylib",
        @"/usr/lib/pspawn_payload-stg2.dylib",
        @"/usr/lib/tweakloader.dylib",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/usr/bin/sbreload",
        @"/bin/bash",
        @"/Applications/Cydia.app",
        @"/cores",
        @"/usr/libexec/cydia"
    ];

    for(NSString* p in jbPaths) {
        [out appendFormat:@"  %@ %@\n", p, [fm fileExistsAtPath:p] ? @"EXISTS" : @"no"];
    }

    NSArray* preboot = [fm contentsOfDirectoryAtPath:@"/private/preboot" error:nil];
    NSMutableArray* jbdirs = [NSMutableArray new];

    for(NSString* d in preboot) {
        if([d hasPrefix:@"jb-"] || [d hasPrefix:@"procursus"]) {
            [jbdirs addObject:d];
        }
    }

    [out appendFormat:@"  /private/preboot jailbreak dirs: %@\n", jbdirs];
}

static void probe_section_4(NSMutableString* out) {
    [out appendString:@"\n== 4. URL scheme probes ==\n"];

    for(NSString* s in @[@"cydia://", @"sileo://", @"zbra://", @"xina://", @"filza://"]) {
        BOOL openable = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:s]];
        [out appendFormat:@"  %-12@ %@\n", s, openable ? @"OPENABLE" : @"no"];
    }
}

static NSMutableArray* probe_section_5(NSMutableString* out, NSArray* hiddenMarkers) {
    [out appendString:@"\n== 5. dladdr/dlsym on hidden images ==\n"];
    // Two independent probes:
    //  A. dladdr on addresses taken from the DIRECT memory read — the
    //     imageLoadAddress (mach_header) of every jailbreak-path entry, plus
    //     an offset into __TEXT — tested BEFORE the dlsym checks below, so a
    //     hidden dlsym result (NULL) can never suppress the dladdr probe.
    //  B. dlsym per candidate symbol, independently; a NULL result only
    //     reports that symbol.
    struct dyld_all_image_infos* infos5 = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
    NSMutableArray* hiddenAddrs = [NSMutableArray new];

    if(infos5 && infos5->infoArray) {
        for(uint32_t i = 0; i < infos5->infoArrayCount; i++) {
            struct dyld_image_info info = infos5->infoArray[i];
            NSString* p = info.imageFilePath ? @(info.imageFilePath) : @"";

            for(NSString* marker in hiddenMarkers) {
                if([p containsString:marker]) {
                    if(info.imageLoadAddress) {
                        [hiddenAddrs addObject:[NSValue valueWithPointer:(void *)((uintptr_t)info.imageLoadAddress + 0x1000)]];
                    }
                    break;
                }
            }
        }
    }

    if(![hiddenAddrs count]) {
        [out appendString:@"  no jailbreak-path images visible in the direct read (memory hiding active, or none loaded) — dladdr probe skipped\n"];
    } else {
        [out appendString:@"  dladdr on hidden-image addresses (direct-read mach_header + __TEXT offset):\n"];

        for(NSValue* v in hiddenAddrs) {
            void* addr = [v pointerValue];
            Dl_info info;
            BOOL got = dladdr(addr, &info);
            [out appendFormat:@"    %p -> %@\n", addr, (got && info.dli_fname) ? @(info.dli_fname) : @"(no info)"];
        }
    }

    for(NSString* symName in @[@"hookObjcMessage", @"MSHookFunction", @"MSHookMessageEx"]) {
        void* sym = dlsym(RTLD_DEFAULT, [symName UTF8String]);

        if(!sym) {
            [out appendFormat:@"  %-20@ not resolvable (hidden or absent)\n", symName];
            continue;
        }

        Dl_info info;
        BOOL gotInfo = dladdr(sym, &info) && info.dli_fname;
        [out appendFormat:@"  %-20@ %p  dladdr: %@\n", symName, sym, gotInfo ? @(info.dli_fname) : @"?"];
    }

    return hiddenAddrs;
}

static void probe_section_6(NSMutableString* out, NSFileManager* fm, NSArray* hiddenMarkers) {
    [out appendString:@"\n== 6. add/remove image stress (unloadable test dylib) ==\n"];
    // The stress library must be a real ON-DISK dylib that dlclose can fully
    // unload: shared-cache images (e.g. /usr/lib/libxml2.dylib) may not be
    // unloadable and behave differently in the infoArray. shdwtestlib ships
    // with the app (second theos target) and is copied to a container path
    // before dlopen, so the path is never in Shadow's restricted domain on
    // either rootful or rootless.
    // theos emits libshdwtestlib.dylib for the LIBRARY_NAME=shdwtestlib
    // library target; the unprefixed spelling is accepted too, so a
    // mismatched install still works. lib-prefixed is preferred (matches
    // what theos actually installs).
    NSArray* testLibNames = @[@"libshdwtestlib.dylib", @"shdwtestlib.dylib"];
    NSString* installedLib = nil;
    NSString* foundLibName = nil;

    // Bundle copy source first (app bundle, then runtime lib dirs — on
    // rootless the install lands under /var/jb/usr/lib), both spellings.
    for(NSString* dir in @[
        [[NSBundle mainBundle] bundlePath],
        @"/usr/lib",
        @"/var/jb/usr/lib"
    ]) {
        for(NSString* name in testLibNames) {
            NSString* cand = [dir stringByAppendingPathComponent:name];

            if([fm fileExistsAtPath:cand]) {
                installedLib = cand;
                foundLibName = name;
                break;
            }
        }

        if(installedLib) {
            break;
        }
    }

    NSString* stressPath = nil;

    if(installedLib) {
        [out appendFormat:@"  stress dylib source: %@ (spelling: %@)\n", installedLib, foundLibName];
        NSString* docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        stressPath = [docs stringByAppendingPathComponent:foundLibName];
        [fm removeItemAtPath:stressPath error:nil];

        NSError* copyErr = nil;

        if(![fm copyItemAtPath:installedLib toPath:stressPath error:&copyErr]) {
            // Rootless: the bundle copy source can sit under /var/jb and be
            // hidden before the copy runs. Log clearly and fall through to
            // the runtime scan below — never abort the stress section.
            [out appendFormat:@"  copy %@ -> %@ FAILED (%@); falling back to runtime scan\n", installedLib, stressPath, copyErr];
            stressPath = nil;
        } else {
            [out appendFormat:@"  stress dylib staged at %@\n", stressPath];
        }
    }

    if(!stressPath) {
        // Fallback: find a non-shared-cache dylib already on disk. A shared-
        // cache image is already in the image list at spawn, so "not in the
        // pre-load infoArray and dlopen succeeds" selects a genuinely
        // loadable/unloadable on-disk image. Hidden-domain paths (restricted
        // by Shadow) are excluded — tracking can't be verified for them.
        [out appendString:@"  shipped test dylib not found; probing for an on-disk dylib...\n"];
        struct dyld_all_image_infos* pre = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
        NSMutableSet* preloaded = [NSMutableSet set];

        if(pre && pre->infoArray) {
            for(uint32_t i = 0; i < pre->infoArrayCount; i++) {
                if(pre->infoArray[i].imageFilePath) {
                    [preloaded addObject:@(pre->infoArray[i].imageFilePath)];
                }
            }
        }

        for(NSString* dir in @[@"/usr/lib", @"/var/jb/usr/lib"]) {
            for(NSString* e in [fm contentsOfDirectoryAtPath:dir error:nil]) {
                if(![e hasSuffix:@".dylib"]) {
                    continue;
                }

                NSString* full = [dir stringByAppendingPathComponent:e];
                BOOL hiddenDomain = [full hasPrefix:@"/var/jb"] || [full hasPrefix:@"/Library/"];
                BOOL jbName = NO;

                for(NSString* marker in hiddenMarkers) {
                    if([full containsString:marker]) {
                        jbName = YES;
                        break;
                    }
                }

                if(hiddenDomain || jbName || [preloaded containsObject:full]) {
                    continue;
                }

                void* h = dlopen([full fileSystemRepresentation], RTLD_NOW);

                if(h) {
                    stressPath = full;
                    dlclose(h);
                    [out appendFormat:@"  fallback stress dylib: %@\n", full];
                    break;
                }
            }

            if(stressPath) {
                break;
            }
        }
    }

    if(!stressPath) {
        [out appendString:@"  SKIPPED: no unloadable on-disk dylib found (install shdwtestlib with the app)\n"];
    } else {
        struct dyld_all_image_infos* base = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
        uint32_t baseCount = (base && base->infoArray) ? base->infoArrayCount : 0;
        [out appendFormat:@"  baseline infoArrayCount = %u (expected range [%u, %u] while stressing)\n", baseCount, baseCount, baseCount + 1];

        // Concurrent direct-memory reader: continuously walks the infoArray
        // while the stress runs, counting torn reads (a mid-walk NULL/NULL
        // entry) and reporting the max entries walked vs the expected range.
        __block _Atomic(BOOL) readerStop = NO;
        __block uint32_t readerRuns = 0;
        __block uint32_t readerTorn = 0;
        __block uint32_t readerMax = 0;
        dispatch_queue_t readerQueue = dispatch_queue_create("dyldprobe.reader", DISPATCH_QUEUE_SERIAL);

        dispatch_async(readerQueue, ^{
            while(!atomic_load_explicit(&readerStop, memory_order_relaxed)) {
                struct dyld_all_image_infos* infos = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");

                if(!infos || !infos->infoArray || infos->infoArrayCount == 0) {
                    continue;
                }

                uint32_t count = infos->infoArrayCount;
                uint32_t walked = 0;
                BOOL torn = NO;
                uint32_t cap = MIN(count, 8192u);

                for(uint32_t i = 0; i < cap; i++) {
                    struct dyld_image_info info = infos->infoArray[i];

                    if(!info.imageLoadAddress && !info.imageFilePath) {
                        torn = YES;
                        break;
                    }

                    walked++;
                }

                if(torn) {
                    readerTorn++;
                }

                if(walked > readerMax) {
                    readerMax = walked;
                }

                readerRuns++;
            }
        });

        BOOL stressOK = YES;
        // The probe marker only exists in the shipped shdwtestlib; the
        // fallback dylib can't export it, so only require it there.
        BOOL expectMarker = [stressPath hasSuffix:testLibNames[0]] || [stressPath hasSuffix:testLibNames[1]];

        for(int i = 0; i < 8; i++) {
            void* handle = dlopen([stressPath fileSystemRepresentation], RTLD_NOW);

            if(!handle) {
                // Capture dlerror() once: a second call clears the first
                // result, so ?: on two calls can log NULL for a real error.
                const char* dlErr = dlerror();
                [out appendFormat:@"  iter %d: dlopen(%@) failed: %s\n", i, stressPath, dlErr ? dlErr : "?"];
                stressOK = NO;
                break;
            }

            // Confirm the handle really is OUR dylib, not a cached image.
            void* marker = dlsym(handle, "shdwtestlib_probe_marker");
            struct dyld_all_image_infos* live = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
            BOOL seenLoaded = NO;

            if(live && live->infoArray) {
                for(uint32_t j = 0; j < live->infoArrayCount; j++) {
                    NSString* p = live->infoArray[j].imageFilePath ? @(live->infoArray[j].imageFilePath) : @"";

                    if([p isEqualToString:stressPath]) {
                        seenLoaded = YES;
                    }

                    for(NSString* marker2 in hiddenMarkers) {
                        if([p containsString:marker2]) {
                            [out appendFormat:@"  iter %d: HIDDEN IMAGE LEAKED: %@\n", i, p];
                            stressOK = NO;
                        }
                    }
                }
            }

            // (a) loaded state: the direct read must show the image while
            // loaded (its container path is never in the hidden domain —
            // absent would mean tracking is broken).
            if(!seenLoaded || (expectMarker && !marker)) {
                [out appendFormat:@"  iter %d: FAILED — %@ not visible in direct infoArray while loaded (marker %@)\n", i, stressPath, marker ? @"OK" : @"MISSING"];
                stressOK = NO;
            }

            dlclose(handle);

            struct dyld_all_image_infos* after = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");
            BOOL stillLoaded = NO;

            if(after && after->infoArray) {
                for(uint32_t j = 0; j < after->infoArrayCount; j++) {
                    NSString* p = after->infoArray[j].imageFilePath ? @(after->infoArray[j].imageFilePath) : @"";

                    if([p isEqualToString:stressPath]) {
                        stillLoaded = YES;
                    }
                }
            }

            // (b) after dlclose: the image must be gone — a shared-cache
            // image (the old libxml2 case) can survive dlclose and stay
            // visible in the read.
            if(stillLoaded) {
                [out appendFormat:@"  iter %d: FAILED — %@ still visible in direct infoArray after dlclose (not unloadable or stale read)\n", i, stressPath];
                stressOK = NO;
            }
        }

        atomic_store_explicit(&readerStop, YES, memory_order_relaxed);
        dispatch_sync(readerQueue, ^{});
        [out appendFormat:@"  concurrent reader: %u runs, max entries walked = %u (expected <= %u), torn reads = %u\n", readerRuns, readerMax, baseCount + 1, readerTorn];

        if(readerTorn > 0) {
            [out appendString:@"  concurrent reader: TORN reads observed — mirror/read published inconsistently\n"];
            stressOK = NO;
        }

        if(readerMax > baseCount + 1) {
            [out appendString:@"  concurrent reader: max exceeded expected range — over-read (count/array mismatch)\n"];
            stressOK = NO;
        }

        [out appendFormat:@"  stress result: %@\n", stressOK ? @"OK" : @"FAILED"];
    }
}

static void probe_section_7(NSMutableString* out) {
    [out appendString:@"\n== 7. uuid / infoArrayChangeTimestamp invariants ==\n"];

    struct dyld_all_image_infos* invariants = dlsym(RTLD_DEFAULT, "dyld_all_image_infos");

    if(invariants) {
        [out appendFormat:@"  version = %u\n", invariants->version];
        [out appendFormat:@"  infoArrayChangeTimestamp = %llu\n", (unsigned long long)invariants->infoArrayChangeTimestamp];
        [out appendFormat:@"  infoArrayCount = %lu, uuidArrayCount = %lu\n", (unsigned long)invariants->infoArrayCount, (unsigned long)invariants->uuidArrayCount];

        if(invariants->uuidArray) {
            for(uint32_t i = 0; i < invariants->uuidArrayCount && i < 4; i++) {
                const unsigned char* u = invariants->uuidArray[i].imageUUID;
                [out appendFormat:@"  uuid[%u] %p: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                    i, invariants->uuidArray[i].imageLoadAddress,
                    u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                    u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]];
            }
        }
    } else {
        [out appendString:@"  (dyld_all_image_infos unavailable)\n"];
    }
}

static void probe_section_8(NSMutableString* out, NSArray* hiddenMarkers, NSMutableArray* hiddenAddrs) {
    [out appendString:@"\n== 8. denyFishHook(dladdr) revert resistance ==\n"];
    // IOSSecuritySuite's FishHookChecker builds a fishhook `rebinding` for
    // "dladdr" pointing at a dummy function and calls rebind_symbols() to
    // revert the symbol. Shadow hooks dladdr/dlsym with INLINE (ElleKit)
    // trampolines, which fishhook-style pointer rebinding cannot undo.
    // Replicate that exact revert, then verify dladdr still resolves
    // coherently. Deliberately LAST so a revert-induced failure can never
    // suppress sections 1-7, and fail-soft throughout: an unavailable
    // rebind_symbols skips the section, and nothing here can abort.
    @try {
        void (*rebindSymbols)(struct rebinding*, int) = (void (*)(struct rebinding*, int))dlsym(RTLD_DEFAULT, "rebind_symbols");

        if(!rebindSymbols) {
            [out appendString:@"  rebind_symbols unavailable — section skipped (no fishhook-linked image in process)\n"];
        } else {
            void* replaced = NULL;
            struct rebinding r = {"dladdr", (void*)dyldprobe_dummy_dladdr, &replaced};
            rebindSymbols(&r, 1);
            [out appendFormat:@"  rebind_symbols({\"dladdr\" -> dummy}) called; replaced = %p %@\n", replaced, replaced ? @"(a binding was patched — the revert really ran)" : @"(no binding patched)"];

            // Targets: ProbeReport itself (a benign app-binary address —
            // Shadow answers it with the app path), plus any jailbreak-path
            // addresses section 5's direct read found — the strongest
            // adjudication: a hidden image leaking out of dladdr after the
            // rebind means the inline hook was reverted.
            NSMutableArray* targets = [NSMutableArray arrayWithObject:[NSValue valueWithPointer:(void*)ProbeReport]];
            [targets addObjectsFromArray:hiddenAddrs];
            BOOL sectionOK = YES;

            for(NSValue* v in targets) {
                void* addr = [v pointerValue];
                Dl_info info;
                BOOL got = dladdr(addr, &info);

                if(!got) {
                    [out appendFormat:@"    %p -> no info (dummy took over — rebind succeeded; expected when no inline hook is active)\n", addr];
                    sectionOK = NO;
                    continue;
                }

                NSString* name = info.dli_fname ? @(info.dli_fname) : @"(null)";
                BOOL jbPath = NO;

                for(NSString* marker in hiddenMarkers) {
                    if([name containsString:marker]) {
                        jbPath = YES;
                        break;
                    }
                }

                if(jbPath) {
                    [out appendFormat:@"    %p -> %@ — JAILBREAK PATH LEAKED through dladdr (revert succeeded)\n", addr, name];
                    sectionOK = NO;
                } else {
                    [out appendFormat:@"    %p -> %@ — resolves; mask/benign answer intact\n", addr, name];
                }
            }

            [out appendFormat:@"  result: %@\n", sectionOK ? @"PASS — dladdr survived the rebind attempt (no crash, coherent Dl_info, hide holds)" : @"FAIL — the rebind disturbed dladdr (inline hook reverted, or no Shadow active)"];
        }
    } @catch(NSException* e) {
        [out appendFormat:@"  EXCEPTION in rebind probe: %@ — FAIL (rebind disturbed dladdr)\n", e];
    }
}

// Section 9: denyFishHook-style GOT revert on a FISHHOOK-rebound C function.
// v5-PLAN AR5 documents the residual: denyFishHook reverts GOT slots only —
// the inline-pinned dladdr/dlsym/dlopen_internal are immune (section 8), but
// the ~60 fishhook-rebound libc/mach/sandbox/mem hooks are revertible. This
// section proves the residual is real and exploitable: rebind the GOT slot
// for access() (a fishhook-rebound libc export) and show the jailbreak-path
// filter is defeated. Deliberately LAST (after section 8) and fail-soft.
static int dyldprobe_dummy_access(const char* path, int mode) {
    return 0;  // "path exists" — the unfiltered answer a reverted access() gives on a JB device
}

static void probe_section_9(NSMutableString* out) {
    [out appendString:@"\n== 9. denyFishHook GOT revert on a fishhook-rebound C function (documented residual) ==\n"];
    @try {
        void (*rebindSymbols)(struct rebinding*, int) = (void (*)(struct rebinding*, int))dlsym(RTLD_DEFAULT, "rebind_symbols");

        if(!rebindSymbols) {
            [out appendString:@"  rebind_symbols unavailable — section skipped\n"];
            return;
        }

        // Baseline: with Shadow active, access() on a jailbreak path is filtered.
        int before = access("/var/jb", F_OK);
        [out appendFormat:@"  access(\"/var/jb\", F_OK) before revert = %d %@\n", before, before == 0 ? @"(path VISIBLE — no filter active)" : @"(filtered — Shadow hook active)"];

        // Replicate denyFishHook: rebind the GOT slot for "access" to a
        // replacement. If the slot was fishhook-rebound by Shadow, rebind
        // finds and patches it (replaced != NULL) — the revert ran.
        void* replaced = NULL;
        struct rebinding r = {"access", (void*)dyldprobe_dummy_access, &replaced};
        rebindSymbols(&r, 1);
        [out appendFormat:@"  rebind_symbols({\"access\" -> dummy}) called; replaced = %p %@\n", replaced, replaced ? @"(GOT slot WAS rebound — fishhook hook revertible)" : @"(no GOT slot patched — hook not fishhook-rebound)"];

        // After: does the JB path now resolve? If yes, the filter is defeated.
        int after = access("/var/jb", F_OK);
        [out appendFormat:@"  access(\"/var/jb\", F_OK) after revert = %d %@\n", after, after == 0 ? @"(path VISIBLE — filter DEFEATED, residual exploited)" : @"(still filtered)"];

        BOOL residual = (replaced != NULL) && (after == 0);
        [out appendFormat:@"  result: %@\n", residual ? @"RESIDUAL CONFIRMED — fishhook-rebound C hooks are revertible by denyFishHook (documented unfixable)" : @"hook survived the revert (inline-pinned, or no Shadow active)"];
    } @catch(NSException* e) {
        [out appendFormat:@"  EXCEPTION in revert probe: %@\n", e];
    }
}

static NSString* ProbeReport(void) {
    NSMutableString* out = [NSMutableString string];
    NSString* appPath = [[NSBundle mainBundle] bundlePath];
    NSFileManager* fm = [NSFileManager defaultManager];

    probe_section_1(out, appPath);
    probe_section_2(out, appPath);
    probe_section_3(out, fm);
    probe_section_4(out);

    // Markers used to recognize jailbreak-path images in the direct reads
    // (shared by sections 5 and 6).
    NSArray* hiddenMarkers = @[
        @"/var/jb", @"libhooker", @"libsubstitute", @"libsubstrate",
        @"libellekit", @"MobileSubstrate", @"pspawn_payload", @"tweakloader"
    ];

    NSMutableArray* hiddenAddrs = probe_section_5(out, hiddenMarkers);
    probe_section_6(out, fm, hiddenMarkers);
    probe_section_7(out);
    probe_section_8(out, hiddenMarkers, hiddenAddrs);
    probe_section_9(out);

    [out appendString:@"\n== done ==\n"];
    return out;
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow* window;
@end

@implementation AppDelegate {
    UITextView* _textView;
}

- (void)_refresh {
    _textView.text = ProbeReport();
    // Instrumentation for SSH-driven verification: dump the full report to
    // stderr AND persist it to a known-writable path so any launch path
    // makes it retrievable without screen capture. NSDocumentDirectory
    // resolution can fail in launch contexts, so use the mobile home dir.
    fprintf(stderr, "%s\n", [_textView.text UTF8String]);
    [[_textView.text dataUsingEncoding:NSUTF8StringEncoding]
        writeToFile:@"/var/mobile/Documents/dyldprobe-report.txt" atomically:YES];
}

- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions {
    // Write the report FIRST — before any window setup — so it lands even if
    // UI initialization stalls (headless/SSH-launched contexts).
    NSString* report;
    @autoreleasepool {
        report = ProbeReport();
        fprintf(stderr, "%s\n", [report UTF8String]);
        [[report dataUsingEncoding:NSUTF8StringEncoding]
            writeToFile:@"/var/mobile/Documents/dyldprobe-report.txt" atomically:YES];
    }
    CGRect frame = [[UIScreen mainScreen] bounds];
    self.window = [[UIWindow alloc] initWithFrame:frame];

    UIViewController* vc = [UIViewController new];
    vc.view = [[UIView alloc] initWithFrame:frame];

    UIButton* refresh = [UIButton buttonWithType:UIButtonTypeSystem];
    refresh.frame = CGRectMake(0, 20, frame.size.width, 44);
    [refresh setTitle:@"Refresh" forState:UIControlStateNormal];
    [refresh addTarget:self action:@selector(_refresh) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:refresh];

    _textView = [[UITextView alloc] initWithFrame:CGRectMake(0, 64, frame.size.width, frame.size.height - 64)];
    _textView.editable = NO;
    _textView.font = [UIFont systemFontOfSize:11];
    // Reuse the launch report; _refresh (Refresh button) builds another on demand.
    _textView.text = report;
    [vc.view addSubview:_textView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char* argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
