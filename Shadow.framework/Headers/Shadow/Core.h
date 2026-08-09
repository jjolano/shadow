#ifndef shadow_core_h
#define shadow_core_h

#import <Foundation/Foundation.h>
#import <Shadow/Backend.h>
#import <Shadow/RestrictionQuery.h>

#define kShadowRestrictionEnableResolve         @"kShadowRestrictionEnableResolve"
#define kShadowRestrictionWorkingDir            @"kShadowRestrictionWorkingDir"
#define kShadowRestrictionNoFollow              @"kShadowRestrictionNoFollow"

// Operation intent for write/create/delete probes. A WRITE probe to a
// restricted-classified path must be denied even when the target does not
// exist (a detector probing for a jailbreak file it could create must not
// get an "allowed" from the existence gates). Default (option absent) = read.
#define kShadowRestrictionOperation             @"kShadowRestrictionOperation"
#define kShadowRestrictionOpRead                @"kShadowRestrictionOpRead"
#define kShadowRestrictionOpWrite               @"kShadowRestrictionOpWrite"

__attribute__((visibility("default")))
@interface Shadow : NSObject {
    ShadowBackend* backend;
}

@property (strong, nonatomic, readonly) NSString* bundlePath;
@property (strong, nonatomic, readonly) NSString* homePath;
@property (strong, nonatomic, readonly) NSString* realHomePath;
@property (assign, nonatomic, readonly) BOOL hasAppSandbox;
@property (assign, nonatomic, readonly) BOOL rootless;

+ (instancetype)sharedInstance;

// C0-2: Shadow-internal read scope flag (see SHADOW_INTERNAL_SCOPE below).
// +[Shadow shdwIsInternalRead] is what the dylib hook layer consults before
// filtering a call; Shadow-owned code sets the flag via the scope macro.
+ (void)shdwEnterInternalRead;
+ (void)shdwExitInternalRead;
+ (BOOL)shdwIsInternalRead;

- (BOOL)isAddrRestricted:(const void *)addr;

- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options;

// Candidate 5 typed entry point: the real pipeline. The legacy dictionary
// methods above translate to a ShadowRestrictionQuery and call this; new
// callers should use it directly (see RestrictionQuery.h for the key-to-field
// mapping). Behavior is identical to the dictionary form.
- (BOOL)isPathRestrictedQuery:(ShadowRestrictionQuery *)query;

- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isURLRestricted:(NSURL *)url options:(NSDictionary<NSString *, id> *)options;

- (BOOL)isSchemeRestricted:(NSString *)scheme;

// C0-3: hidden-app predicate — case-insensitive match against the well-known
// package-manager/loader bundle IDs (static list) or any ruleset's
// BlacklistBundleIDs (user-extensible).
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;

// C0-3: protected-name policy — YES when the path is restricted by a ruleset
// OR its basename matches one of Shadow's own artifacts (Shadow.dylib,
// Shadow.framework, libSandy.dylib, HookKit.framework,
// substrate/substitute/ellekit), case-insensitive prefix match on the
// basename so rootful and rootless (/var/jb) prefixes both resolve to it.
- (BOOL)isProtectedImagePath:(NSString *)path;
@end

// C0-2 internal read scope (see the note above the interface). The cleanup
// attribute runs when the scope variable leaves scope — including on early
// return/break from inside the wrapped block — so the busy flag can never
// get stuck set; the flag itself is depth-counted in Core.m, so nested
// scopes stay busy until the outermost one exits.
#define SHADOW_INTERNAL_SCOPE \
    for(BOOL _shdw_scope_active __attribute__((cleanup(shdw_scope_leave))) = ([Shadow shdwEnterInternalRead], YES); \
        _shdw_scope_active; \
        _shdw_scope_active = NO)

static inline void shdw_scope_leave(BOOL* b) {
    (void) b;
    [Shadow shdwExitInternalRead];
}
#endif
