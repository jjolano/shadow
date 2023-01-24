#import <Foundation/Foundation.h>

#import "ShadowService.h"

@interface Shadow : NSObject
@property (nonatomic, readwrite, strong) ShadowService* service;
@property (nonatomic, readwrite, assign) BOOL runningInApp;
@property (nonatomic, readwrite, assign) BOOL tweakCompatibility;
@property (nonatomic, readwrite, assign) BOOL rootlessMode;
@property (nonatomic, readwrite, assign) BOOL enhancedPathResolve;

- (BOOL)isCallerTweak:(NSArray*)backtrace;

- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path resolve:(BOOL)resolve;
- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isAddrRestricted:(const void *)addr;

+ (instancetype)shadowWithService:(ShadowService *)_service;
@end
