#import <Foundation/Foundation.h>

#import "ShadowService.h"

@interface Shadow : NSObject
@property BOOL tweakCompatibility;

- (BOOL)isCallerTweak:(NSArray*)backtrace;

- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path resolve:(BOOL)resolve;
- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isAddrRestricted:(const void *)addr;

- (void)setOrigFunc:(NSString *)fname withAddr:(void *)addr;
- (void *)getOrigFunc:(NSString *)fname elseAddr:(void *)addr;

+ (instancetype)shadowWithService:(ShadowService *)_service;
@end
