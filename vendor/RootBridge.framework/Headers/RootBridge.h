#ifndef rootbridge_h
#define rootbridge_h

#import <Foundation/Foundation.h>

@interface RootBridge : NSObject
+ (BOOL)isJBRootless;
+ (NSString *)getJBPath:(NSString *)path;
@end

#endif
