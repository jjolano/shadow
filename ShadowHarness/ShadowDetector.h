// On-device port of the host test-battery detector (tests/detectors/):
// compiled verbatim into the ShadowHarness app. In the harness, access()/
// open() go through Shadow's libc hooks when the payload is active, and the
// scheme check consults Shadow's engine directly — i.e. the detector runs
// against the real on-device filter, which is the point.
//
// Independent jailbreak-detection checks for the harness detector battery.
//
// Implements the classic, publicly documented jailbreak-detection
// techniques (file-existence probes, restricted-dir writability, URL
// schemes) in Foundation+libc ObjC so the harness can run a realistic
// detector against Shadow's engine.
//
// NOTE ON LICENSING: this is NOT a port of IOSSecuritySuite. That library
// is distributed under a restrictive EULA (no modification/redistribution
// rights; paid tiers), so its code cannot be vendored here. The checks and
// probe paths below are independent implementations of well-known
// jailbreak-detection techniques and public jailbreak-artifact facts that
// predate and are shared across every JB detector (including
// IOSSecuritySuite, whose public documentation was consulted for the probe
// path selection).

#ifndef shadow_detector_h
#define shadow_detector_h

#import <Foundation/Foundation.h>

// One check result; `jailbroken` is YES when the check FIRED (an indicator
// was found). The reason names the first offending path/check.
typedef struct {
    BOOL jailbroken;
    char reason[512];
} ShdwDetectorResult;

// Runs all checks. The behavior depends on the harness environment:
//   - file checks go through the virtual filesystem (mapped fixture jbroot)
//     and the shadow filter (engine-restricted paths report ENOENT/EACCES)
//   - the scheme check consults Shadow's engine (isSchemeRestricted)
// Returns jailbroken=YES if ANY check fired.
ShdwDetectorResult ShdwDetectorRun(void);

// Audit variant: runs EVERY probe (including the emulator-group paths, for
// ruleset-gap detection) and returns one dictionary per probe:
// { @"probe": <name>, @"fired": NSNumber(BOOL), @"detail": <path/scheme> }.
// No early return — a ruleset-gap audit needs the full picture.
NSArray* ShdwDetectorAudit(void);

#endif
