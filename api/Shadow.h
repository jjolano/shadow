#import <Foundation/Foundation.h>

#import "ShadowService.h"

@interface Shadow : NSObject
@property ShadowService* service;
@property BOOL runningInApp;
@property BOOL tweakCompatibility;
@property BOOL rootlessMode;
@property BOOL enhancedPathResolve;

- (BOOL)isCallerTweak:(NSArray*)backtrace;

- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path resolve:(BOOL)resolve;
- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isAddrRestricted:(const void *)addr;

+ (instancetype)shadowWithService:(ShadowService *)_service;
@end
