#ifndef shadow_core_h
#define shadow_core_h

#import <Foundation/Foundation.h>
#import <Shadow/Backend.h>

#define kShadowRestrictionEnableResolve         @"kShadowRestrictionEnableResolve"
#define kShadowRestrictionWorkingDir            @"kShadowRestrictionWorkingDir"
#define kShadowRestrictionFileExtension         @"kShadowRestrictionFileExtension"
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

- (BOOL)isAddrExternal:(const void *)addr;
- (BOOL)isAddrRestricted:(const void *)addr;

- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options;

- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isURLRestricted:(NSURL *)url options:(NSDictionary<NSString *, id> *)options;

- (BOOL)isSchemeRestricted:(NSString *)scheme;
@end
#endif
