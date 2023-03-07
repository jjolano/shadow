#ifndef shadow_backend_h
#define shadow_backend_h

#import <Foundation/Foundation.h>

@interface ShadowBackend : NSObject
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isURLSchemeRestricted:(NSString *)scheme;
@end
#endif
