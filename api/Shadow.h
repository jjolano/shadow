#import <Foundation/Foundation.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

#define BYPASS_VERSION  "2.7"

@class NSString, NSArray;

@interface Shadow : NSObject
- (void)setMessagingCenter:(CPDistributedMessagingCenter *)center;
- (void)setURLSchemes:(NSArray<NSString *>*)u;
- (BOOL)isCallerTweak:(NSArray<NSNumber *>*)backtrace;
- (NSString *)resolvePath:(NSString *)path;
- (BOOL)isCPathRestricted:(const char *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path resolve:(BOOL)resolve;
- (BOOL)isURLRestricted:(NSURL *)url;
@end
