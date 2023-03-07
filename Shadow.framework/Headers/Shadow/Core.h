#ifndef shadow_core_h
#define shadow_core_h

#import <Foundation/Foundation.h>

#define kShadowRestrictionEnableResolve         @"kShadowRestrictionEnableResolve"
#define kShadowRestrictionWorkingDir            @"kShadowRestrictionWorkingDir"
#define kShadowRestrictionFileExtension         @"kShadowRestrictionFileExtension"

@interface Shadow : NSObject
@property (nonatomic, readonly) NSString* bundlePath;
@property (nonatomic, readonly) NSString* homePath;
@property (nonatomic, readonly) NSString* realHomePath;
@property (nonatomic, readonly) BOOL hasAppSandbox;
@property (nonatomic, readonly) BOOL rootless;

+ (instancetype)sharedInstance;

- (BOOL)isCallerAddrExternal;

- (BOOL)isAddrExternal:(const void *)addr;
- (BOOL)isAddrRestricted:(const void *)addr;

- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options;

- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isURLRestricted:(NSURL *)url options:(NSDictionary<NSString *, id> *)options;

- (BOOL)isURLSchemeRestricted:(NSString *)scheme;
@end
#endif
