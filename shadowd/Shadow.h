@interface Shadow : NSObject
+ (instancetype)sharedInstance;
- (NSDictionary *)handleMessageNamed:(NSString *)name withUserInfo:(NSDictionary *)userInfo;
@end
