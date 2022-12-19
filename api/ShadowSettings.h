#import <Foundation/Foundation.h>
#import "ShadowService.h"

@interface ShadowSettings : NSObject
+ (NSDictionary *)getDefaultPreferences;
+ (NSUserDefaults *)getUserDefaults;
+ (NSDictionary *)getPreferences:(NSString *)bundleIdentifier;
+ (NSDictionary *)getPreferences:(NSString *)bundleIdentifier usingService:(ShadowService *)service;
@end
