#import <Foundation/Foundation.h>

#define BYPASS_VERSION  "4.6"
#define API_VERSION "5.0"

#define SHADOW_PREFS_PLIST "/var/mobile/Library/Preferences/me.jjolano.shadow.plist"
#define CPDMC_SERVICE_NAME "me.jjolano.shadow.service"
#define LOCAL_SERVICE_DB "/Library/Shadow/db.plist"

#ifdef DEBUG
#define NSLog(...) NSLog(__VA_ARGS__)
#else
#define NSLog(...) (void)0
#endif

@interface ShadowService : NSObject
@property BOOL rootless;

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
