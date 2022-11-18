#import <Foundation/Foundation.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#define BYPASS_VERSION  "4.1"

@class NSString, NSArray;

@interface Shadow : NSObject
- (BOOL)isPathSafe:(NSString *)path;
- (BOOL)isPathHardRestricted:(NSString *)path;
- (BOOL)isCallerTweak:(NSArray<NSNumber *>*)backtrace;
- (NSString *)resolvePath:(NSString *)path;
- (BOOL)isPathSandbox:(NSString *)path;
- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path resolve:(BOOL)resolve;
- (BOOL)isURLRestricted:(NSURL *)url;
- (void)setTweakCompat:(BOOL)enabled;
- (void)setTweakCompatExtra:(BOOL)enabled;
@end
