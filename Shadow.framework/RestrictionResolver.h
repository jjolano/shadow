#ifndef shadow_restriction_resolver_h
#define shadow_restriction_resolver_h

#import <Foundation/Foundation.h>

// Per-process resolution context, captured once from the Shadow facade
// (Candidate 5: Core.m is the public facade/context).
typedef struct {
    BOOL hasAppSandbox;
    BOOL rootless;
    NSString* bundlePath;
    NSString* homePath;
} ShadowRestrictionContext;

// Path-resolution stage of the new engine: normalization (tilde expansion,
// relative-path joining, standardization), sandbox exemption, and the
// resolve-before-exempt alias (realpath) step with its reentrancy guard.
// Framework-internal; no evaluation here.
__attribute__((visibility("hidden")))
@interface ShadowRestrictionResolver : NSObject

- (instancetype)initWithContext:(ShadowRestrictionContext)context;

// Tilde-expands; returns nil when the path still starts with '~' (unresolvable
// user) — callers deny. Mirrors the legacy pipeline's two-step test.
- (NSString *)expandTilde:(NSString *)path;

// Joins a relative path to the working directory (absolute) or the process
// cwd when none/relative is given.
- (NSString *)joinWorkingDirectory:(NSString *)path workingDirectory:(NSString *)wd;

// Standardizes (NSURL canonicalization + /private prefix collapse) via
// +[Shadow getStandardizedPath:] — the exact legacy transform.
- (NSString *)standardizePath:(NSString *)path;

// YES when the path is inside the app bundle or home directory and the app is
// sandboxed (legacy shouldCheckPath == NO).
- (BOOL)isSandboxExempt:(NSString *)path;

// realpath() the path (the "aliases" step: resolve-before-exempt). Guarded by
// a per-thread flag so the libc realpath hook re-entering the engine from
// inside realpath cannot recurse forever. Returns nil when resolution fails
// (nonexistent path keeps its exemption).
- (NSString *)resolveTarget:(NSString *)path;
@end
#endif