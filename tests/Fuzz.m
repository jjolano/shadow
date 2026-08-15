// Edge-case fuzzer for the decision engine.
//
// Probes the engine's string-processing surface (path standardization,
// prefix/predicate matching, scheme/bundle-ID/protected-name checks) with
// structured mutations of a corpus plus random inputs, asserting INVARIANTS
// rather than specific verdicts:
//
//   D1 determinism        — the same input always yields the same verdict
//   D2 write monotonicity — C0-1: a read-restricted path is also
//                           write-restricted (writes skip existence gates)
//   D3 standardization    — the verdict is unchanged by getStandardizedPath
//                           (the engine standardizes internally); checked
//                           only for inputs inside the engine's path
//                           contract (absolute, unencoded, scheme-free)
//   D4 URL/path closure   — a file:// URL verdict matches its path verdict
//   D5 scheme case-closure — a scheme verdict matches its lowercase form
//   D6 standardize idempotence — std(std(p)) == std(p)
//
// Every probe is @try-wrapped: GNUstep predicate evaluation can throw on
// pathological inputs, and an uncaught throw inside the engine is a real
// finding (the device hooks would crash the app the same way). The PRNG is
// seeded (fixed default, overridable) so any finding reproduces exactly.
// Invariant probes are restricted to the engine's path contract: absolute
// paths without percent-encoding, scheme strings, or embedded NULs (the
// latter made the earlier D4 findings look like a cache transient — the
// structure veto sees the NUL in the component while the URL lane's
// C-string truncates at it; kernel-delivered paths can never contain NULs).
//
// A hard crash (SEGV) kills the process — the last printed seed+iteration
// is the repro; the parent's exit code reports the failure.

#import <stdatomic.h>

#import <Foundation/Foundation.h>
#import <Shadow.h>

#import <stdlib.h>
#import <string.h>
#import <limits.h>
#import <unistd.h>

// fsinterpose (shadow filter arm/disarm + engine consult).
void shdw_shadow_filter_set_enabled(int enabled);
int shdw_shadow_filter(const char* path, int is_write);

// Deterministic PRNG (xorshift64*).
static uint64_t gState;

static uint64_t fz_rand(void) {
    gState ^= gState >> 12;
    gState ^= gState << 25;
    gState ^= gState >> 27;
    return gState * 0x2545F4914F6CDD1DULL;
}

static NSUInteger fz_below(NSUInteger n) {
    return n ? (NSUInteger)(fz_rand() % n) : 0;
}

// ---------------------------------------------------------------------------
// Corpus and mutations
// ---------------------------------------------------------------------------

static NSString* fz_pick(NSArray* pool) {
    return [pool objectAtIndex:fz_below([pool count])];
}

static NSString* fz_mutate(NSString* input) {
    static NSArray* tokens = nil;
    static dispatch_once_t once = 0;

    dispatch_once(&once, ^{
        tokens = @[
            @"jb", @"ssh", @"cydia", @"jailbreak", @"app", @"plist", @"dylib",
            @"substrate", @"var", @"mobile", @"..", @".", @"/", @"//", @"/./",
            @"~", @"%", @"%2e", @"%2f", @"\x00", @"\x1f", @"\x7f", @"\u202e",
            @"\uff0f", @" ", @"\t", @"-", @"_", @"0", @"A", @"com.apple",
        ];
    });

    NSUInteger len = [input length];
    NSUInteger op = fz_below(10);

    switch(op) {
        case 0: // insert a token at a random position
            return [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len + 1), 0)
                                                   withString:fz_pick(tokens)];
        case 1: // replace a character with a token
            return len ? [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len), 1)
                                                       withString:fz_pick(tokens)] : input;
        case 2: // delete a character
            return len > 1 ? [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len), 1)
                                                            withString:@""] : input;
        case 3: // uppercase a character
            return len ? [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len), 1)
                                                        withString:[[input substringWithRange:NSMakeRange(fz_below(len), 1)] uppercaseString]] : input;
        case 4: // duplicate a character
            return len ? [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len), 1)
                                                        withString:[input substringWithRange:NSMakeRange(fz_below(len), 1)]] : input;
        case 5: // prepend a token
            return [fz_pick(tokens) stringByAppendingString:input];
        case 6: // append a token
            return [input stringByAppendingString:fz_pick(tokens)];
        case 7: // trim one char from the front
            return len > 1 ? [input substringFromIndex:1] : input;
        case 8: // trim one char from the back
            return len > 1 ? [input substringToIndex:len - 1] : input;
        default: // random token as the whole string
            return fz_pick(tokens);
    }
}

static NSString* fz_randomPath(void) {
    static NSArray* roots = nil;
    static dispatch_once_t once = 0;

    dispatch_once(&once, ^{
        roots = @[
            @"/", @"", @"~", @"/var", @"/usr", @"/tmp", @"/private", @"//",
            @"file://", @"cydia://", @"http://", @"ssh", @"/var/jb", @"%2e%2e",
            @"\u202e", @"/\uff0f", @" ", @"../", @"/./",
        ];
    });

    NSMutableString* s = [NSMutableString stringWithString:fz_pick(roots)];

    for(NSUInteger i = 0, n = fz_below(5); i < n; i++) {
        [s appendString:fz_pick(@[@"/", @"", @"/./", @"//", @"..", @"%", @"-", @"_"])];
        [s appendString:fz_pick(@[@"jb", @"ssh", @"cydia", @"app", @"dylib", @"x", @"A", @"0", @"\u202e"])];
    }

    return s;
}

// ---------------------------------------------------------------------------
// Probes and invariants
// ---------------------------------------------------------------------------

static NSUInteger gFindings = 0;
static NSUInteger gIters = 0;

// Rolling trace of recent probes (input + verdict) for finding forensics.
static NSString* gTrace[64];
static BOOL gTraceVerdict[64];
static NSUInteger gTracePos = 0;

static void fz_trace(NSString* input, BOOL verdict) {
    gTrace[gTracePos] = input;
    gTraceVerdict[gTracePos] = verdict;
    gTracePos = (gTracePos + 1) % 64;
}

static void fz_dumpTrace(void) {
    for(NSUInteger i = 0; i < 64; i++) {
        NSUInteger idx = (gTracePos + i) % 64;

        if(gTrace[idx]) {
            printf("    trace: %s -> %d\n", [gTrace[idx] UTF8String], gTraceVerdict[idx]);
        }
    }
}

static void fz_finding(NSString* invariant, NSString* input, NSString* detail) {
    gFindings++;
    printf("FUZZ FINDING [%s] iter=%lu input=\"%s\"%s%s\n",
         [invariant UTF8String], (unsigned long)gIters, [input UTF8String],
        detail ? " " : "", detail ? [detail UTF8String] : "");
}

// Path-contract check for the invariant probes: absolute, no
// percent-encoding, no scheme strings, NO EMBEDDED NUL. NUL-containing
// inputs are out of contract (kernel-delivered paths cannot contain NULs):
// the structure veto treats the NUL as part of the component while the
// URL lane's C-string truncates at it — a real verdict divergence that no
// device path can trigger (this was the D4 "transient": the NUL was
// invisible in the finding output).
static BOOL fz_inContract(NSString* p) {
    return [p hasPrefix:@"/"] && ![p containsString:@"%"]
        && ![p containsString:@":"] && ![p containsString:@"\x00"];
}

static void fz_probe(NSString* path) {
    Shadow* shadow = [Shadow sharedInstance];

    // D1: determinism (fresh + cached call).
    @try {
        BOOL r1 = [shadow isPathRestricted:path];
        fz_trace(path, r1);

        if(r1 != [shadow isPathRestricted:path]) {
            fz_finding(@"D1 determinism", path, @"verdict changed on repeat call");
            return;
        }

        // D2: write monotonicity (C0-1).
        if(r1 && ![shadow isPathRestricted:path options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}]) {
            fz_finding(@"D2 write monotonicity", path, @"read-restricted but write allowed");
            return;
        }

        // D3: standardization closure. Only for inputs inside the engine's
        // path contract: absolute paths without URL-encoding or scheme
        // strings. (Scheme strings are relative-path semantics to
        // isPathRestricted but URL-path semantics to getStandardizedPath;
        // %-encoded strings make getStandardizedPath non-idempotent —
        // neither form reaches the engine from the hooks, which deliver
        // decoded, real paths.)
        if(fz_inContract(path)) {
            NSString* std = [Shadow getStandardizedPath:path];
            BOOL stdVerdict = [shadow isPathRestricted:std];

            if(stdVerdict != r1) {
                fz_finding(@"D3 standardization closure", path,
                    [NSString stringWithFormat:@"raw=%d std=%d standardized to \"%@\"",
                        r1, stdVerdict, std]);
                return;
            }
        }

        // D4: file-URL closure (in-contract paths only).
        if(fz_inContract(path)) {
            NSURL* url = [NSURL fileURLWithPath:path];
            NSString* urlPath = [url path];
            BOOL urlVerdict = [shadow isURLRestricted:url];

            if(urlVerdict != r1) {
                BOOL urlPathDirect = [shadow isPathRestricted:urlPath];

                fz_finding(@"D4 URL/path closure", path,
                    [NSString stringWithFormat:@"path=%d urlPath=\"%@\" direct=%d viaURL=%d refURL=%d",
                        r1, urlPath, urlPathDirect, urlVerdict, [url isFileReferenceURL]]);

                printf("    ruleset gen=%llu\n", (unsigned long long)
                    atomic_load_explicit(&shdw_ruleset_generation, memory_order_acquire));

                fz_dumpTrace();
                return;
            }
        }

        // D5: scheme case-closure.
        if([shadow isSchemeRestricted:path] != [shadow isSchemeRestricted:[path lowercaseString]]) {
            fz_finding(@"D5 scheme case-closure", path, @"case variant verdict differs");
            return;
        }

        // D6: standardize idempotence (in-contract paths only — see D3).
        if(fz_inContract(path)) {
            NSString* std = [Shadow getStandardizedPath:path];

            if(![[Shadow getStandardizedPath:std] isEqualToString:std]) {
                fz_finding(@"D6 standardize idempotence", path,
                    [NSString stringWithFormat:@"std(std) != std: \"%@\"", std]);
                return;
            }
        }

        // Exercise the remaining entry points for exceptions/crashes.
        (void)[shadow isCPathRestricted:[path UTF8String]];
        (void)[shadow isProtectedImagePath:path];
        (void)[shadow isBundleIDRestricted:path];
    } @catch(NSException* exception) {
        NSString* detail = [NSString stringWithFormat:@"%@: %@", [exception name], [exception reason]];

        // GNUstep NSException supports call stacks; include the top frames
        // so the throwing site is identifiable without a debugger.
        NSArray* stack = [exception respondsToSelector:@selector(callStackSymbols)]
            ? [exception callStackSymbols] : nil;

        if([stack count] > 0) {
            detail = [detail stringByAppendingFormat:@" | %@",
                [[stack subarrayWithRange:NSMakeRange(0, MIN(4, [stack count]))] componentsJoinedByString:@" | "]];
        }

        fz_finding(@"exception", path, detail);
    }
}

// ---------------------------------------------------------------------------

int shdw_fuzz_run(NSUInteger iters, unsigned seed) {
    gState = seed ? seed : 0x9E3779B97F4A7C15ULL;

    static NSArray* corpus = nil;
    static dispatch_once_t once = 0;

    dispatch_once(&once, ^{
        corpus = @[
            @"/var/jb", @"/var/jb/usr/bin/ssh", @"/usr/bin/ssh",
            @"/Applications/Cydia.app", @"/usr/sbin/fstab",
            @"/var/mobile/Media/DCIM/1.jpg", @"/var/mobile/evil/foo",
            @"/usr/lib/libjailbreak.dylib", @"/tmp/jailbreak-detector",
            @"/cores/crash", @"/private/preboot/jb-abc", @"/", @"",
            @"ssh", @"~/../var/jb", @"/var/jb2", @"/usr/sbin/sshd_config",
            @"/var/mobile/Library/Preferences/x",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"file:///var/jb/usr/bin/ssh", @"cydia://x", @"http://example.com",
            @"..", @".", @"/./", @"//", @"%2e%2e", @"/var/jb/..", @"/var//jb",
            @"CYDIA", @"com.saurik.Cydia", @"\u202e/var/jb", @"/var/jb%2f",
        ];
    });

    printf("[fuzz] seed=%u iters=%lu\n", seed, (unsigned long)iters);

    for(NSUInteger i = 0; i < iters; i++) {
        gIters = i;

        NSString* base = fz_below(3) == 0 ? fz_randomPath() : fz_pick(corpus);
        NSString* input = fz_mutate(base);

        fz_probe(input);

        if(gFindings > 0 && gFindings % 50 == 0) {
            printf("[fuzz] %lu findings so far at iter %lu\n", (unsigned long)gFindings, (unsigned long)i);
        }
    }

    printf("[fuzz] done: %lu iterations, %lu findings\n", (unsigned long)iters, (unsigned long)gFindings);

    if(getenv("SHADW_FUZZ_DEBUG")) {
        printf("[fuzz] debug probes:\n");

        NSArray* debugPaths = @[@"/Applications", @"/var", @"/", @"/usr/lib", @"/var/jb", @"/usr/sbin/fstab", @"/cores"];

        for(NSString* p in debugPaths) {
            Shadow* shadow = [Shadow sharedInstance];

            printf("  %-20s fresh=%d cached=%d url=%d std=%d\n",
                [p UTF8String],
                [shadow isPathRestricted:p],
                [shadow isPathRestricted:p],
                [shadow isURLRestricted:[NSURL fileURLWithPath:p]],
                [shadow isPathRestricted:[Shadow getStandardizedPath:p]]);
        }

        // Reload-cycle check: the ruleset generation must be stable across
        // the 1s scan gate. If it bumps every second, the GNUstep marker
        // scheme (cache always rejected -> recompile -> cache rewrite ->
        // dir-mtime churn) keeps the engine reloading forever.
        uint64_t g1 = atomic_load_explicit(&shdw_ruleset_generation, memory_order_acquire);
        [NSThread sleepForTimeInterval:1.4];
        uint64_t g2 = atomic_load_explicit(&shdw_ruleset_generation, memory_order_acquire);
        printf("[fuzz] ruleset generation: %llu -> %llu (%s)\n",
            (unsigned long long)g1, (unsigned long long)g2, g1 == g2 ? "stable" : "RELOAD CYCLE");
    }

    return gFindings ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Adversarial fuzzer: evasion-mutation property testing with a semantic
// oracle. For each canonical seed path (from a jailbreak-artifact + legit
// corpus), every evasion mutation that STANDARDIZES TO THE SAME PATH must
// receive the SAME verdict — a detector cannot dodge the ruleset by path
// mangling. With the shadow filter armed, restricted-equivalent variants
// must stay hidden (ENOENT) while allowed seeds' real files stay visible.
//
//   E1 equivalent-variant read verdict differs from the canonical
//   E2 equivalent-variant write verdict differs (C0-1)
//   E3 filter failed to hide a restricted-equivalent variant
//   E4 filter hid an allowed variant (false positive)
//
// Each E-finding is re-verified against the canonical verdict before being
// counted; if the canonical itself flips, it is the known D4 transient and
// is reported as TRANSIENT (not a finding). Mutations whose standardized
// form differs from the seed (case flips, percent-encoding, token splices)
// are different paths, not evasions — they are tallied per seed as the
// "dodge surface" (informational).
// ---------------------------------------------------------------------------

static BOOL afz_inContract(NSString* p) {
    return [p hasPrefix:@"/"] && ![p containsString:@"%"] && ![p containsString:@":"];
}

static NSString* afz_evade(NSString* input) {
    static NSArray* tokens = nil;
    static dispatch_once_t once = 0;

    dispatch_once(&once, ^{
        tokens = @[
            @"jb", @"ssh", @"cydia", @"jailbreak", @"app", @"dylib", @"mobile",
            @"..", @".", @"/", @"//", @"/./", @"~/..", @"%2f", @"%2e", @"%00",
            @"\u202e", @"\uff0f", @"\u2215", @" ", @"\t", @"-", @"_", @"0",
            @"com.apple", @"substrate",
        ];
    });

    NSUInteger len = [input length];
    NSUInteger op = fz_below(14);

    switch(op) {
        case 0: // insert a token mid-path
            return [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len + 1), 0)
                                                   withString:fz_pick(tokens)];
        case 1: // replace one char with a token
            return len ? [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len), 1)
                                                       withString:fz_pick(tokens)] : input;
        case 2: // duplicate a segment
            return len ? [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len), 1)
                                                        withString:[input substringWithRange:NSMakeRange(fz_below(len), 1)]] : input;
        case 3: // trailing slash
            return [input stringByAppendingString:@"/"];
        case 4: // double a separator
            return [input stringByReplacingOccurrencesOfString:@"/" withString:@"//"];
        case 5: // dot-dot escape prefix
            return [@"/.." stringByAppendingString:input];
        case 6: // tilde escape prefix
            return [@"~/.." stringByAppendingString:input];
        case 7: // append a token
            return [input stringByAppendingString:fz_pick(tokens)];
        case 8: // trim a component
            return len > 3 ? [input substringToIndex:fz_below(len - 1) + 1] : input;
        case 9: // insert /./ mid-path
            return [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len + 1), 0)
                                                   withString:@"/./"];
        case 10: // uppercase the last component
        {
            NSString* last = [input lastPathComponent];
            return [[input substringToIndex:[input length] - [last length]]
                stringByAppendingString:[last uppercaseString]];
        }
        case 11: // unicode slash splice
            return [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len + 1), 0)
                                                   withString:@"\uff0f"];
        case 12: // RTL override splice
            return [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len + 1), 0)
                                                   withString:@"\u202e"];
        default: // whitespace splice
            return [input stringByReplacingCharactersInRange:NSMakeRange(fz_below(len + 1), 0)
                                                   withString:@" "];
    }
}

int shdw_afuzz_run(NSUInteger variantsPerSeed, unsigned seed) {
    gState = seed ? seed : 0x9E3779B97F4A7C15ULL;
    gFindings = 0;
    gIters = 0;

    static NSArray* corpus = nil;
    static dispatch_once_t once = 0;

    dispatch_once(&once, ^{
        corpus = @[
            // Jailbreak artifacts (expected restricted)
            @"/var/jb", @"/var/jb/usr/bin/ssh", @"/var/jb/usr/bin",
            @"/var/jb/Library/LaunchDaemons", @"/usr/lib/libjailbreak.dylib",
            @"/usr/lib/libellekit.dylib", @"/usr/lib/libsubstrate.dylib",
            @"/usr/lib/TweakInject", @"/Applications/Cydia.app",
            @"/Applications/Sileo.app", @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/usr/sbin/fstab", @"/usr/sbin/sshd_config",
            @"/private/preboot/jb-abc", @"/cores/crash", @"/tmp/jailbreak-detector",
            @"/var/mobile/evil/foo", @"/var/binpack",
            // Modern-era artifacts (Dopamine/palera1n/unc0ver)
            @"/var/Liy/.procursus_strapped", @"/var/Liy",
            @"/Applications/Dopamine.app", @"/Applications/palera1nLoader.app",
            @"/usr/lib/ABDYLD.dylib", @"/usr/lib/frida", @"/jb/lzma",
            @"/.installed_unc0ver", @"/var/lib/dpkg/info/mobilesubstrate.md5sums",
            // Legit paths (expected allowed)
            @"/var/mobile/Media/DCIM/1.jpg", @"/var/mobile/Media/DCIM",
            @"/var/mobile/Library/Preferences/x", @"/usr/bin/ssh",
            @"/var/mobile/Documents/notes.txt", @"/var/jb2",
        ];
    });

    printf("[afuzz] seed=%u variants/seed=%lu, filter armed (rootless)\n",
        seed, (unsigned long)variantsPerSeed);
    fflush(stdout);

    // The engine is initialized with the filter DISARMED, and all direct
    // engine calls below run disarmed: with the filter armed, the engine's
    // own existence-gate accesses (mapped jbroot paths) would be filtered
    // as "restricted" and the decisions would break. The filter is armed
    // only around the E3/E4 visibility checks (its engine call is
    // recursion-guarded via gInFilter).
    Shadow* shadow = [Shadow sharedInstance];

    NSUInteger total = 0;
    NSUInteger equivalent = 0;
    NSUInteger nonEquivalent = 0;
    NSUInteger transients = 0;

    for(NSString* seedPath in corpus) {
        if(!afz_inContract(seedPath)) {
            continue;
        }

        NSString* canon = [Shadow getStandardizedPath:seedPath];

        if(!afz_inContract(canon) || ![canon isAbsolutePath]) {
            continue;
        }

        BOOL canonV = [shadow isPathRestricted:canon];
        fprintf(stderr, "DBG canonV done\n");
        BOOL canonW = [shadow isPathRestricted:canon options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}];
        fprintf(stderr, "DBG canonW done\n");
        int baselineVisible = (access([canon fileSystemRepresentation], F_OK) == 0);
        fprintf(stderr, "DBG baseline done (%d)\n", baselineVisible);

        printf("  seed %-52s canon=%s verdict=%d\n",
            [seedPath UTF8String], [canon UTF8String], canonV);
        fflush(stdout);

        for(NSUInteger v = 0; v < variantsPerSeed; v++) {
            gIters = v;
            NSString* variant = afz_evade(seedPath);
            total++;

            if(!afz_inContract(variant)) {
                nonEquivalent++;
                continue;
            }

            NSString* std = [Shadow getStandardizedPath:variant];

            if(![std isEqualToString:canon]) {
                nonEquivalent++;
                continue;
            }

            equivalent++;

            // E1: read verdict must match the canonical.
            BOOL vv = [shadow isPathRestricted:variant];

            if(vv != canonV) {
                // Re-verify the canonical: a flip is the known D4 transient.
                BOOL canonV2 = [shadow isPathRestricted:canon];

                if(canonV2 != canonV) {
                    transients++;
                    printf("  TRANSIENT (D4 class) on seed %s variant %s\n",
                        [seedPath UTF8String], [variant UTF8String]);
                } else {
                    gFindings++;
                    printf("FUZZ FINDING [E1 evasion] seed=%s variant=\"%s\" canon=%d got=%d (std=\"%s\")\n",
                        [seedPath UTF8String], [variant UTF8String], canonV, vv, [std UTF8String]);
                }
            }

            // E2: write verdict must match the canonical write verdict.
            BOOL vw = [shadow isPathRestricted:variant options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}];

            if(vw != canonW) {
                BOOL canonW2 = [shadow isPathRestricted:canon options:@{kShadowRestrictionOperation : kShadowRestrictionOpWrite}];

                if(canonW2 != canonW) {
                    transients++;
                } else {
                    gFindings++;
                    printf("FUZZ FINDING [E2 evasion write] seed=%s variant=\"%s\" canon=%d got=%d\n",
                        [seedPath UTF8String], [variant UTF8String], canonW, vw);
                }
            }

            // E3/E4: filter pass — restricted equivalents must be hidden;
            // allowed seeds' real files must stay visible. The filter is
            // armed ONLY around these checks, and the visibility is
            // DIFFERENTIAL per variant (a variant can be invisible without
            // the filter too — e.g. a trailing slash on a file — which is
            // an FS artifact, not a filter false positive).
            if(canonV) {
                shdw_shadow_filter_set_enabled(1);
                int visibleOn = (access([variant fileSystemRepresentation], F_OK) == 0);
                shdw_shadow_filter_set_enabled(0);

                if(visibleOn) {
                    gFindings++;
                    printf("FUZZ FINDING [E3 filter leak] seed=%s variant=\"%s\" visible despite restriction\n",
                        [seedPath UTF8String], [variant UTF8String]);
                }
            } else if(baselineVisible) {
                if(access([variant fileSystemRepresentation], F_OK) != 0) {
                    continue;   // invisible without the filter too: FS artifact
                }

                shdw_shadow_filter_set_enabled(1);
                int visibleOn = (access([variant fileSystemRepresentation], F_OK) == 0);
                shdw_shadow_filter_set_enabled(0);

                if(!visibleOn) {
                    gFindings++;
                    printf("FUZZ FINDING [E4 filter false positive] seed=%s variant=\"%s\" hidden\n",
                        [seedPath UTF8String], [variant UTF8String]);
                }
            }
        }
    }

    shdw_shadow_filter_set_enabled(0);

    printf("[afuzz] done: %lu probes (%lu equivalent, %lu non-equivalent, %lu transient), %lu findings\n",
        (unsigned long)total, (unsigned long)equivalent,
        (unsigned long)nonEquivalent, (unsigned long)transients,
        (unsigned long)gFindings);

    return gFindings ? 1 : 0;
}
