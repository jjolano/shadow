#import "Battery.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/syscall.h>
#import <mach-o/dyld.h>

#import <Shadow.h>

#import "ShadowDetector.h"

// ---------------------------------------------------------------------------
// Hooks-payload presence
// ---------------------------------------------------------------------------

BOOL ShdwIsShadowCoreLoaded(void) {
	// The stub (Shadow.dylib) dlopens ShadowCore.dylib beside itself when
	// the ctor gate passes; scan dyld's image list for it. ponytail: plain
	// strstr — a false positive needs a sibling image whose path contains
	// "ShadowCore", which the harness's own bundle path does not.
	for(uint32_t i = 0; i < _dyld_image_count(); i++) {
		const char* name = _dyld_get_image_name(i);
		if(name && strstr(name, "ShadowCore")) {
			return YES;
		}
	}
	return NO;
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
			NSString* urlString = [NSString stringWithFormat:@"%@://", detail];
			filteredFound = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:urlString]];
			filteredResult = filteredFound ? @"YES" : @"NO";
			if(shadow) {
				engineRestricted = [shadow isSchemeRestricted:detail];
			}
			engineResult = engineRestricted ? @"restricted" : @"allowed";
		} else {
			rawFound = shdw_raw_open([detail UTF8String]) >= 0;
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
		if(!shadow) {
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
