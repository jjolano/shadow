#import <Foundation/Foundation.h>

#ifdef DEBUG
#define NSLog(...) NSLog(__VA_ARGS__)
#else
#define NSLog(...) (void)0
#endif

@interface ShadowService : NSObject
- (void)startService;
- (void)connectService;
- (void)startLocalService;

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args;

- (NSString *)resolvePath:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (NSArray *)getURLSchemes;
- (NSDictionary *)getVersions;
@end
