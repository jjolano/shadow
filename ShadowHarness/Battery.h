// Shadow Harness model: raw syscall probes, canonical probe list, detector
// battery runner and the diagnostics dump builder. UI-free — consumed by
// StatusViewController.

#import <Foundation/Foundation.h>

// Raw syscall probes. Shadow hooks libc (access/open/syscall); a direct
// arm64 `svc #0x80` (x16 = syscall number, x0..x5 = args, negative errno in
// x0 on failure) bypasses every hook and answers with kernel truth.
// Non-arm64 builds (legacy armv7/armv7s slices) have no svc asm: -1 (absent).
long shdw_raw_open(const char* path);      // SYS_open(5), O_RDONLY
long shdw_raw_unlink(const char* path);    // SYS_unlink(10)

// Evidence I/O uses Shadow's internal-read scope so the hooks under test do
// not hide their own nonce context or output report.
NSData* ShdwReadEvidenceData(NSString* path);
BOOL ShdwWriteEvidenceData(NSData* data, NSString* path);

// YES when Shadow's hooks payload (ShadowCore.dylib) is loaded into this
// process — the stub dlopens it when its ctor path gate passes. The harness
// links Shadow.framework directly, so class presence alone does not mean
// the hooks are active.
BOOL ShdwIsShadowCoreLoaded(void);

// Engine class lookup that survives Shadow's own class hiding: with the
// payload active, NSClassFromString/objc_getClass are hooked and hide
// Shadow's classes from external callers — including this harness. Shadow
// deliberately does NOT hook objc_getRequiredClass (its abort contract is
// useless to detectors), so it is the internal path. When the payload is
// inactive no hiding is armed and stock lookup is truthful.
Class ShdwShadowClass(const char* name);

// Writable Documents path for this jailbreak platform app.
NSString* ShdwDocumentsDirectory(void);

// Canonical jailbreak-artifact probes (user-facing section). One dict per
// row: { @"probe": path-or-scheme, @"isScheme": NSNumber(BOOL),
//        @"verdict": @"hidden"|@"visible"|@"n/a" }.
NSArray<NSDictionary*>* ShdwCanonicalProbes(void);

// Detector-battery verdict rows (dev-mode section). One dict per probe:
// { @"name": probe label, @"group": display group ("exists"/"system"/
//   "readable"/"scheme"), @"raw": NSString, @"filtered": NSString,
//   @"engine": NSString, @"fired": NSNumber(BOOL) (audit's own verdict),
//   @"verdict": @"PASS"|@"GAP"|@"HOOK-GAP"|@"INFO"|@"MIXED",
//   @"reason": NSString }.
NSArray<NSDictionary*>* ShdwBatteryRows(void);

// Current machine-readable producer report. Returns nil when the driver did
// not install a complete nonce-bound run context in Shadow's preferences.
NSDictionary* ShdwStealthReport(void);

// Plain-text dump of a section model (as built by StatusViewController) for
// the "Copy diagnostics" button.
NSString* ShdwDiagnosticsDump(NSArray<NSDictionary*>* sections);
