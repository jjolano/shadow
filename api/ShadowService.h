#import <Foundation/Foundation.h>

#define BYPASS_VERSION  "4.1"
#define API_VERSION "3.0"

#define CPDMC_SERVICE_NAME "me.jjolano.shadow.service"

@interface ShadowService : NSObject
- (void)startService;
- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args;
- (NSString *)resolvePath:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (NSArray*)getURLSchemes;
- (NSDictionary *)getVersions;
@end
