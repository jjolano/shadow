#import <Foundation/Foundation.h>

#define BYPASS_VERSION  "4.4"
#define API_VERSION "3.2"

#define SHADOW_PREFS_PLIST "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
#define CPDMC_SERVICE_NAME "me.jjolano.shadow.service"
#define LOCAL_SERVICE_DB "/Library/Shadow/db.plist"

@interface ShadowService : NSObject
- (void)startService;
- (void)connectService;
- (void)startLocalService;
- (NSDictionary *)generateDatabase;

- (NSDictionary *)sendIPC:(NSString *)messageName withArgs:(NSDictionary *)args;

- (NSString *)resolvePath:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path;
- (NSArray*)getURLSchemes;
- (NSDictionary *)getVersions;

+ (NSDictionary *)getDefaultPreferences;
+ (NSUserDefaults *)getPreferences;
@end
