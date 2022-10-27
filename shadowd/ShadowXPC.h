#import "../api/Shadow.h"
#import <Foundation/Foundation.h>

@interface ShadowXPC : Shadow
- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo;
@end
