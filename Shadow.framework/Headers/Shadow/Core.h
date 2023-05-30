#ifndef shadow_core_h
#define shadow_core_h

#import <Foundation/Foundation.h>
#import <Shadow/Backend.h>

#define kShadowRestrictionEnableResolve         @"kShadowRestrictionEnableResolve"
#define kShadowRestrictionWorkingDir            @"kShadowRestrictionWorkingDir"
#define kShadowRestrictionFileExtension         @"kShadowRestrictionFileExtension"

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
