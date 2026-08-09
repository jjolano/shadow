#ifndef shadow_restriction_query_h
#define shadow_restriction_query_h

#import <Foundation/Foundation.h>

// Typed restriction query (Candidate 5: restriction/rules runtime). Replaces
// the stringly-typed option dictionaries on the ENTRY side: the legacy
// -[Shadow isPathRestricted:options:] family translates to a
// ShadowRestrictionQuery internally, and the typed entry point
// -[Shadow isPathRestrictedQuery:] is the real pipeline. The dictionary keys
// (kShadowRestriction*) remain exported in Core.h for the hook layer; they
// are translated here and never leak into the pipeline.
//
//   kShadowRestrictionEnableResolve absent/YES  -> ShadowRestrictionFlagResolve set
//   kShadowRestrictionNoFollow @YES             -> ShadowRestrictionFlagNoFollow set
//   kShadowRestrictionOperation OpWrite         -> ShadowRestrictionOperationWrite
//   kShadowRestrictionWorkingDir                -> workingDirectory (absolute)
//
// Anything else in a legacy options dictionary is ignored by evaluation (the
// old pipeline only read these four keys); the only behavioral effect of
// extra keys was disabling the decision cache for that query, which the typed
// pipeline preserves by caching only default-shaped queries.

typedef NS_ENUM(NSInteger, ShadowRestrictionOperation) {
    ShadowRestrictionOperationRead = 0,
    ShadowRestrictionOperationWrite = 1
};

typedef NS_OPTIONS(NSUInteger, ShadowRestrictionFlags) {
    // Re-resolve via stringByStandardizingPath and re-evaluate (legacy
    // kShadowRestrictionEnableResolve semantics). Set by default.
    ShadowRestrictionFlagResolve = 1 << 0,
    // Location-only answer for the link itself; skip realpath resolution
    // (legacy kShadowRestrictionNoFollow semantics; libc readlink/lstat lane).
    ShadowRestrictionFlagNoFollow = 1 << 1
};

__attribute__((visibility("default")))
@interface ShadowRestrictionQuery : NSObject

@property (copy, nonatomic) NSString* path;
// Absolute working directory for relative paths; nil = process cwd is used.
@property (copy, nonatomic) NSString* workingDirectory;
@property (assign, nonatomic) ShadowRestrictionOperation operation;
@property (assign, nonatomic) ShadowRestrictionFlags flags;

+ (instancetype)queryWithPath:(NSString *)path;
@end
#endif