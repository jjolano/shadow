#import <Foundation/Foundation.h>
#import "ShadowService.h"

#define kShadowRestrictionEnableResolve @"kShadowRestrictionEnableResolve"
#define kShadowRestrictionWorkingDir    @"kShadowRestrictionWorkingDir"

@interface Shadow : NSObject
@property (nonatomic, readwrite, strong) ShadowService* service;
@property (nonatomic, readwrite, assign) BOOL runningInApp;
@property (nonatomic, readwrite, assign) BOOL tweakCompatibility;
@property (nonatomic, readwrite, assign) BOOL rootlessMode;
@property (nonatomic, readwrite, assign) BOOL enhancedPathResolve;

- (BOOL)isCallerTweak:(const void *)ret_addr;

- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path options:(NSDictionary<NSString *, id> *)options;
- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isURLRestricted:(NSURL *)url options:(NSDictionary<NSString *, id> *)options;
- (BOOL)isAddrRestricted:(const void *)addr;

+ (instancetype)shadowWithService:(ShadowService *)_service;
@end
