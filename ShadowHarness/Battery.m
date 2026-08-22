#import "Battery.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <stdlib.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/syscall.h>
#import <mach/mach_time.h>

#import <Shadow.h>

#import "ShadowDetector.h"

static uint64_t gHarnessProbeStart = 0;
static mach_timebase_info_data_t gHarnessTimebase = {0, 0};

__attribute__((constructor)) static void shdw_harness_probe_clock_start(void) {
	gHarnessProbeStart = mach_continuous_time();
	mach_timebase_info(&gHarnessTimebase);
}

static uint64_t shdw_harness_elapsed_ns(uint64_t end) {
	if(!gHarnessProbeStart || !gHarnessTimebase.denom || end < gHarnessProbeStart) {
		return 0;
	}
	uint64_t ticks = end - gHarnessProbeStart;
	return (ticks / gHarnessTimebase.denom) * gHarnessTimebase.numer +
		((ticks % gHarnessTimebase.denom) * gHarnessTimebase.numer) / gHarnessTimebase.denom;
}

NSString* ShdwDocumentsDirectory(void) {
	// The verification driver (tests/stealth-device.sh) stages the launch
	// context to and reads the diagnostics report from a fixed
	// /var/mobile/Documents for this bundle, in every launch mode. Do NOT use
	// NSSearchPathForDirectoriesInDomains here: under a sandboxed SpringBoard
	// launch it resolves to the app's data container, and under the direct
	// producer launch it resolves to $CFFIXED_USER_HOME/Documents — neither
	// matches where the driver put the context, so the read returns nothing
	// and the headless producer exits(2) without a report. The harness is a
	// system app on the jailbroken test rig and can reach /var/mobile/Documents
	// in both modes (verified on device).
	return @"/var/mobile/Documents";
}

// ---------------------------------------------------------------------------
// Hooks-payload presence
// ---------------------------------------------------------------------------

BOOL ShdwIsShadowCoreLoaded(void) {
	// ShadowCore deliberately hides its images from the public dyld list, so
	// an image scan is circular. Its always-on class-identity hooks suppress
	// Shadow.framework classes from ordinary lookup, while the deliberately
	// unhooked fatal lookup still returns this known-present class.
	return objc_getRequiredClass("Shadow") && !objc_getClass("Shadow");
}

static NSDictionary* shdw_activation_snapshot(void) {
    if(!ShdwIsShadowCoreLoaded()) {
        return nil;
    }

    __block NSDictionary* snapshot = nil;
    SHADOW_INTERNAL_SCOPE {
        Class coordinator = objc_getRequiredClass("SHDWHookCoordinator");
        SEL selector = sel_registerName("shdw_activationSnapshot");

        if(coordinator && [coordinator respondsToSelector:selector]) {
            typedef NSDictionary* (*SnapshotMessage)(id, SEL);
            snapshot = ((SnapshotMessage)objc_msgSend)(coordinator, selector);
        }
    }

    return [snapshot isKindOfClass:[NSDictionary class]] ? snapshot : nil;
}

static NSArray<NSString*>* shdw_activation_inventory(NSDictionary* snapshot, NSString* key) {
    id value = snapshot[key];
    return [value isKindOfClass:[NSArray class]] ? value : @[];
}

static NSDictionary* shdw_activation_observation(void) {
    NSDictionary* snapshot = shdw_activation_snapshot();
    NSArray<NSString*>* ctor = shdw_activation_inventory(snapshot, @"ctor_inventory");
    NSArray<NSString*>* postLoad = shdw_activation_inventory(snapshot, @"post_load_inventory");
    NSArray<NSString*>* postDetector = shdw_activation_inventory(snapshot, @"post_detector_inventory");
    NSSet* ctorSet = [NSSet setWithArray:ctor];
    NSSet* postLoadSet = [NSSet setWithArray:postLoad];
    NSSet* postDetectorSet = [NSSet setWithArray:postDetector];
    BOOL ctorObserved = [snapshot[@"ctor_observed"] boolValue];
    BOOL postLoadObserved = [snapshot[@"post_load_observed"] boolValue];
    BOOL postDetectorObserved = [snapshot[@"post_detector_observed"] boolValue];
    BOOL ctorCore = [ctorSet containsObject:@"dyld"] && [ctorSet containsObject:@"objc"] && [ctorSet containsObject:@"classes"];
    BOOL postLoadCore = [ctorSet isSubsetOfSet:postLoadSet] && [postLoadSet containsObject:@"Hook_URLScheme"];
    BOOL postDetectorCore = [postLoadSet isSubsetOfSet:postDetectorSet] && [postDetectorSet containsObject:@"Hook_Filesystem@objc"] && [postDetectorSet containsObject:@"Hook_HideApps"];

    return @{
        @"case_id" : @"activation",
        @"ctor_inventory" : ctor,
        @"post_load_inventory" : postLoad,
        @"post_detector_inventory" : postDetector,
        @"verdicts" : @{
            @"ctor_event" : ctorObserved ? @"PASS" : @"FAIL",
            @"ctor_core_units" : ctorCore ? @"PASS" : @"FAIL",
            @"post_load_event" : postLoadObserved ? @"PASS" : @"FAIL",
            @"post_load_progression" : postLoadCore ? @"PASS" : @"FAIL",
            @"post_detector_event" : postDetectorObserved ? @"PASS" : @"FAIL",
            @"post_detector_progression" : postDetectorCore ? @"PASS" : @"FAIL",
        },
    };
}

Class ShdwShadowClass(const char* name) {
	if(!name || !name[0]) {
		return nil;
	}
	if(ShdwIsShadowCoreLoaded()) {
		// Hiding group armed: name lookup is filtered for external callers.
		// The class is guaranteed present (the harness links the framework),
		// so the abort contract of objc_getRequiredClass cannot fire here.
		return objc_getRequiredClass(name);
	}
	return NSClassFromString(@(name));
}

// ---------------------------------------------------------------------------
// Raw syscall probes
// ---------------------------------------------------------------------------

#if defined(__arm64__)
// Direct arm64 syscall: `svc #0x80` with the syscall number in x16 and
// arguments in x0..x5. On arm64 Darwin the kernel signals errors with the
// CARRY flag set and the positive errno in x0 (libc's wrapper negates after
// `b.lo`); x86_64 instead returns negative errno in rax. The probe must not
// assume the x86 convention — it has never run on arm64 before (host tests
// are x86 and take the #else branch). `cset` materializes the carry flag so
// *error is reliable under either convention: with carry-set semantics,
// error=YES → -1; with negative-errno semantics, ret<0 → the caller's
// `>= 0` check also reads absent. Success always yields the real fd.
static inline long shdw_raw_syscall(long number, long a0, long a1, long a2, BOOL* error) {
	register long x16 __asm__("x16") = number;
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	unsigned flag = 0;
	__asm__ volatile(
		"svc #0x80\n"
		"cset %w[flag], cs"
		: "+r"(x0), [flag] "=r"(flag)
		: "r"(x16), "r"(x1), "r"(x2)
		: "memory", "cc");
	*error = (flag != 0);
	return x0;
}
#endif

long shdw_raw_open(const char* path) {
#if defined(__arm64__)
	if(!path) {
		return -1;
	}
	BOOL error = NO;
	long ret = shdw_raw_syscall(SYS_open, (long)path, O_RDONLY, 0, &error);
	return error ? -1 : ret;
#else
	// ponytail: non-arm64 slices (legacy armv7/armv7s, simulators) get no svc
	// asm — report absent. Raw probing is arm64-only by design.
	return -1;
#endif
}

long shdw_raw_unlink(const char* path) {
#if defined(__arm64__)
	if(!path) {
		return -1;
	}
	BOOL error = NO;
	long ret = shdw_raw_syscall(SYS_unlink, (long)path, 0, 0, &error);
	return error ? -1 : ret;
#else
	return -1;
#endif
}

NSData* ShdwReadEvidenceData(NSString* path) {
	NSData* data = nil;
	SHADOW_INTERNAL_SCOPE {
		data = [NSData dataWithContentsOfFile:path options:0 error:nil];
	}
	return data;
}

BOOL ShdwWriteEvidenceData(NSData* data, NSString* path) {
	BOOL written = NO;
	SHADOW_INTERNAL_SCOPE {
		written = [data writeToFile:path options:NSDataWritingAtomic error:nil];
	}
	return written;
}

// ---------------------------------------------------------------------------
// Canonical probes
// ---------------------------------------------------------------------------

NSArray<NSDictionary*>* ShdwCanonicalProbes(void) {
	// Classic detector paths/schemes, one per row. Expected verdict with a
	// working ruleset: all "hidden". Nothing beyond that is claimed.
	static const char* const kCanonicalPaths[] = {
		"/var/jb",
		"/var/jb/usr/bin",
		"/var/lib/apt",
		"/etc/apt",
		"/usr/libexec/cydia",
		"/Applications/Cydia.app",
	};
	static const char* const kCanonicalSchemes[] = {
		"cydia",
		"sileo",
	};

	NSMutableArray* rows = [NSMutableArray new];
	Shadow* shadow = ShdwShadowClass("Shadow") ? [ShdwShadowClass("Shadow") sharedInstance] : nil;

	for(NSUInteger i = 0; i < sizeof(kCanonicalPaths) / sizeof(kCanonicalPaths[0]); i++) {
		NSString* path = [NSString stringWithUTF8String:kCanonicalPaths[i]];
		NSString* verdict = @"n/a";
		if(shadow) {
			verdict = [shadow isPathRestricted:path] ? @"hidden" : @"visible";
		}
		[rows addObject:@{
			@"probe" : path,
			@"isScheme" : @NO,
			@"verdict" : verdict,
		}];
	}

	for(NSUInteger i = 0; i < sizeof(kCanonicalSchemes) / sizeof(kCanonicalSchemes[0]); i++) {
		NSString* scheme = [NSString stringWithUTF8String:kCanonicalSchemes[i]];
		NSString* verdict = @"n/a";
		if(shadow) {
			verdict = [shadow isSchemeRestricted:scheme] ? @"hidden" : @"visible";
		}
		[rows addObject:@{
			@"probe" : [scheme stringByAppendingString:@"://"],
			@"isScheme" : @YES,
			@"verdict" : verdict,
		}];
	}

	return rows;
}

// ---------------------------------------------------------------------------
// Detector battery
// ---------------------------------------------------------------------------

NSArray<NSDictionary*>* ShdwBatteryRows(void) {
	Shadow* shadow = ShdwShadowClass("Shadow") ? [ShdwShadowClass("Shadow") sharedInstance] : nil;
	UIApplication* application = [UIApplication sharedApplication];
	NSMutableArray* rows = [NSMutableArray new];

	// The full probe audit from the ported detector. The writable group is
	// dropped on-device: the app sandbox denies writes regardless of Shadow,
	// so "can I write /var/jb" is answered by the sandbox, not the engine —
	// useless signal, kept only in the host battery.
	for(NSDictionary* entry in ShdwDetectorAudit()) {
		NSString* probe = entry[@"probe"];        // e.g. "exists /var/jb"
		NSString* detail = entry[@"detail"];      // e.g. "/var/jb"
		BOOL fired = [entry[@"fired"] boolValue];

		// Group = leading token; the emulator-only group ("exists(emu)")
		// is displayed as "system" — those paths exist legitimately on
		// real devices.
		NSString* rawGroup = [[probe componentsSeparatedByString:@" "] firstObject];
		if([rawGroup isEqualToString:@"writable"]) {
			continue;
		}
		NSString* group = [rawGroup isEqualToString:@"exists(emu)"] ? @"system" : rawGroup;
		BOOL isScheme = [group isEqualToString:@"scheme"];

		NSString* rawResult = @"-";
		NSString* filteredResult;
		NSString* engineResult;
		BOOL rawFound = NO;
		BOOL filteredFound = NO;
		BOOL engineRestricted = NO;

		if(isScheme) {
			// No syscall exists for URL schemes; the filtered column
			// (canOpenURL) is the only reachability signal.
			if(application) {
				NSString* urlString = [NSString stringWithFormat:@"%@://", detail];
				filteredFound = [application canOpenURL:[NSURL URLWithString:urlString]];
				filteredResult = filteredFound ? @"YES" : @"NO";
			} else {
				filteredResult = @"unavailable";
			}
			if(shadow) {
				engineRestricted = [shadow isSchemeRestricted:detail];
			}
			engineResult = engineRestricted ? @"restricted" : @"allowed";
		} else {
			long rawFD = shdw_raw_open([detail UTF8String]);
			rawFound = rawFD >= 0;
			if(rawFound) {
				close((int)rawFD);
			}
			rawResult = rawFound ? @"found" : @"absent";
			int mode = [group isEqualToString:@"readable"] ? R_OK : F_OK;
			filteredFound = access([detail UTF8String], mode) == 0;
			filteredResult = filteredFound ? @"found" : @"clean";
			if(shadow) {
				engineRestricted = [shadow isPathRestricted:detail];
			}
			engineResult = engineRestricted ? @"restricted" : @"allowed";
		}

		NSString* verdict;
		NSString* reason;
		if(isScheme && !application) {
			verdict = @"INFO";
			reason = @"UIApplication not initialized";
		} else if(!shadow) {
			verdict = @"INFO";
			reason = @"Shadow not loaded — engine n/a";
		} else if(isScheme) {
			if(filteredFound && engineRestricted) {
				verdict = @"HOOK-GAP";
				reason = @"engine restricts but scheme reachable";
			} else if(filteredFound) {
				verdict = @"GAP";
				reason = @"ruleset missing this scheme";
			} else if(engineRestricted) {
				verdict = @"PASS";
				reason = @"scheme hidden";
			} else {
				verdict = @"INFO";
				reason = @"no handler on this device";
			}
		} else if(!rawFound) {
			verdict = @"INFO";
			reason = @"not on this device (absent or sandboxed)";
		} else if(rawFound && !filteredFound) {
			// The filtered surface is the detector-visible answer: if libc
			// cannot see the path, the probe is defeated regardless of the
			// engine's raw verdict. The engine may defer (rootless existence
			// gates: path absent under /var/jb → rulesets not consulted) or
			// restrict; either way the observable is clean. The engine state
			// stays in the detail column for diagnostics.
			verdict = @"PASS";
			reason = engineRestricted
				? @"raw found, libc clean, engine restricts"
				: @"raw found, libc clean, engine defers (existence gate)";
		} else if(rawFound && filteredFound && !engineRestricted) {
			verdict = @"GAP";
			reason = @"ruleset missing this path";
		} else {
			verdict = @"HOOK-GAP";
			reason = @"engine restricts but libc still shows it";
		}

		[rows addObject:@{
			@"name" : probe,
			@"group" : group,
			@"raw" : rawResult,
			@"filtered" : filteredResult,
			@"engine" : engineResult,
			@"fired" : @(fired),
			@"verdict" : verdict,
			@"reason" : reason,
		}];
	}

	return rows;
}

NSDictionary* ShdwStealthReport(void) {
	uint64_t reportEnd = mach_continuous_time();
	NSString* bundleID = [NSBundle mainBundle].bundleIdentifier;
	NSString* documents = ShdwDocumentsDirectory();
	NSData* contextData = documents ? ShdwReadEvidenceData(
		[documents stringByAppendingPathComponent:@".ShadowStealthContext.json"]) : nil;
	NSDictionary* fileContext = contextData ?
		[NSJSONSerialization JSONObjectWithData:contextData options:0 error:nil] : nil;
	NSDictionary* context = [fileContext isKindOfClass:[NSDictionary class]] ? @{
		@"_StealthRunID" : fileContext[@"run_id"] ?: @"",
		@"_StealthRowID" : fileContext[@"row_id"] ?: @"",
		@"_StealthMode" : fileContext[@"requested_mode"] ?: @"",
		@"_StealthNonce" : fileContext[@"nonce"] ?: @"",
		@"_StealthProbeRevision" : fileContext[@"probe_revision"] ?: @"",
	} : nil;
	if(!context) {
		NSUserDefaults* defaults = [[NSUserDefaults alloc]
			initWithSuiteName:@"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"];
		context = bundleID ? [defaults dictionaryForKey:bundleID] : nil;
	}
	NSArray<NSString*>* contextKeys = @[
		@"_StealthRunID", @"_StealthRowID", @"_StealthMode",
		@"_StealthNonce", @"_StealthProbeRevision",
	];
	for(NSString* key in contextKeys) {
		if(![context[key] isKindOfClass:[NSString class]] || ![context[key] length]) {
			return nil;
		}
	}

	NSString* mode = context[@"_StealthMode"];
	if(![mode isEqualToString:@"uninjected"] && ![mode isEqualToString:@"injected"]) {
		return nil;
	}
	NSString* forcedFailureID = [fileContext[@"force_failure_id"] isKindOfClass:[NSString class]] ?
		fileContext[@"force_failure_id"] : nil;

	NSArray<NSDictionary*>* batteryRows = ShdwBatteryRows();
	NSDictionary* activation = [mode isEqualToString:@"injected"] ? shdw_activation_observation() : nil;
	NSMutableArray* observations = [NSMutableArray arrayWithCapacity:batteryRows.count];
	NSUInteger pass = 0, fail = 0, skip = 0;
	BOOL forcedFailureMatched = NO;
	for(NSDictionary* row in batteryRows) {
		NSString* verdict = row[@"verdict"];
		NSString* status;
		BOOL forcedFailure = forcedFailureID.length && [forcedFailureID isEqualToString:row[@"name"]];
		if(forcedFailure) {
			status = @"FAIL";
			fail++;
			forcedFailureMatched = YES;
		} else if([verdict isEqualToString:@"PASS"]) {
			status = @"PASS";
			pass++;
		} else if([verdict isEqualToString:@"INFO"]) {
			status = @"SKIP";
			skip++;
		} else {
			status = @"FAIL";
			fail++;
		}
		[observations addObject:@{
			@"id" : row[@"name"] ?: @"(unnamed)",
			@"group" : row[@"group"] ?: @"unknown",
			@"status" : status,
			@"raw" : row[@"raw"] ?: [NSNull null],
			@"filtered" : row[@"filtered"] ?: [NSNull null],
			@"engine" : row[@"engine"] ?: [NSNull null],
			@"reason" : forcedFailure ? @"forced failure control" : (row[@"reason"] ?: @""),
		}];
	}

	BOOL loaded = ShdwIsShadowCoreLoaded();
	BOOL activationFailure = NO;
	for(id verdict in [activation[@"verdicts"] allValues]) {
		if(![verdict isEqual:@"PASS"]) {
			activationFailure = YES;
			break;
		}
	}
	BOOL setupFailure = batteryRows.count == 0 ||
		(forcedFailureID.length && !forcedFailureMatched) ||
		([mode isEqualToString:@"injected"] && !loaded) ||
		([mode isEqualToString:@"uninjected"] && loaded) || activationFailure;
	NSString* aggregate = setupFailure ? @"SETUP-FAIL" :
		([mode isEqualToString:@"uninjected"] ? @"CONTROL-INACTIVE" :
		 (fail ? @"FAIL" : @"PASS"));
	NSInteger producerExit = setupFailure ? 2 : fail ? 1 : 0;
	id canary = [mode isEqualToString:@"uninjected"] ? @"CONTROL-INACTIVE" : @{
		@"status" : loaded ? @"PASS" : @"FAIL",
		@"shadow_core_loaded" : @(loaded),
	};

	NSMutableDictionary* report = [@{
		@"schema_version" : @1,
		@"producer" : @"ShadowHarness",
		@"run_id" : context[@"_StealthRunID"],
		@"row_id" : context[@"_StealthRowID"],
		@"row_type" : @"jailbroken",
		@"requested_mode" : mode,
		@"nonce" : context[@"_StealthNonce"],
		@"probe_revision" : context[@"_StealthProbeRevision"],
		@"canary" : canary,
		@"observations" : @{
			@"aggregate" : aggregate,
			@"timing" : @{
				@"clock" : @"mach_continuous_time",
				@"start_ticks" : @(gHarnessProbeStart), @"end_ticks" : @(reportEnd),
				@"probe_elapsed_ns" : @(shdw_harness_elapsed_ns(reportEnd)),
			},
			@"summary" : @{
				@"pass" : @(pass), @"fail" : @(fail), @"skip" : @(skip),
				@"setup_fail" : @(setupFailure ? 1 : 0),
			},
			@"rows" : observations,
		},
		@"producer_exit" : @(producerExit),
	} mutableCopy];
	if(activation) {
		NSMutableDictionary* reportObservations = [report[@"observations"] mutableCopy];
		reportObservations[@"activation"] = activation;
		report[@"observations"] = reportObservations;
	}
	return report;
}

// ---------------------------------------------------------------------------
// Diagnostics dump
// ---------------------------------------------------------------------------

NSString* ShdwDiagnosticsDump(NSArray<NSDictionary*>* sections) {
	NSMutableString* dump = [NSMutableString string];
	[dump appendString:@"Shadow Harness diagnostics\n==========================\n"];

	for(NSDictionary* section in sections) {
		[dump appendFormat:@"\n## %@\n", section[@"title"]];
		for(NSDictionary* row in section[@"rows"]) {
			NSString* text = row[@"text"];
			NSString* detail = row[@"detail"];
			if(detail.length) {
				[dump appendFormat:@"  %@ — %@\n", text, detail];
			} else {
				[dump appendFormat:@"  %@\n", text];
			}
		}
	}

	return dump;
}
