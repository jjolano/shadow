#ifndef shadow_core_h
#define shadow_core_h

#import <Foundation/Foundation.h>

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

// C0-5: ruleset generation, bumped on every reload (RulesetStore.m). Exported
// as a plain atomic — same reasoning as the internal-read flag below, plus one
// of its own: the dylib's restricted-image range cache reads this on every
// intercepted call to decide whether its snapshot is still valid, and an
// ObjC message send (or the store's @synchronized) on that path would give
// back the cost the cache exists to remove.
__attribute__((visibility("default")))
extern _Atomic(uint64_t) shdw_ruleset_generation;

// C0-2: internal-read scope depth (Core.m). Read directly by the dylib's
// isCallerExternal() — non-zero means this thread is inside
// SHADOW_INTERNAL_SCOPE and must be shown truth. The +shdwIsInternalRead
// class method below is the same value; it stays for the harness and for any
// caller that would rather not link the symbol, but the ~400 hook entry
// points call the exported C accessor instead, because an objc_msgSend there
// costs more than everything else those hooks do. (Exported as a FUNCTION,
// not the TLS variable: theos links the dylib against Shadow.tbd, whose
// format cannot carry thread-local exports.)
__attribute__((visibility("default")))
NSUInteger shdwInternalBusy(void);

__attribute__((visibility("default")))
@interface Shadow : NSObject

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
