#import <Foundation/Foundation.h>

#define API_VERSION "1.0"

@interface ShadowXPC : NSObject
- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo;
@end
