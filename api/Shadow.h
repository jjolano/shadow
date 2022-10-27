#import <Foundation/Foundation.h>
#import <AppSupport/CPDistributedMessagingCenter.h>

@class NSString, NSArray;

@interface Shadow : NSObject
- (void)setMessagingCenter:(CPDistributedMessagingCenter *)center;
- (BOOL)isPathRestricted:(NSString *)path;
+ (instancetype)sharedInstance;
@end
