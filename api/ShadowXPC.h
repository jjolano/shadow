#import "Shadow.h"
#import <Foundation/Foundation.h>

@interface ShadowXPC : NSObject
- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo;
@end
