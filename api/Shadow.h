#import <Foundation/Foundation.h>

#import "ShadowService.h"

@interface Shadow : NSObject
- (BOOL)isCallerTweak:(NSArray*)backtrace;
- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path resolve:(BOOL)resolve;
- (BOOL)isURLRestricted:(NSURL *)url;

- (void)setTweakCompatExtra:(BOOL)enabled;
- (void)setOrigFunc:(NSString *)fname withAddr:(void *)addr;
- (void *)getOrigFunc:(NSString *)fname;

+ (instancetype)shadowWithService:(ShadowService *)_service;
@end
