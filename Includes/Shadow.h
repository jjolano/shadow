#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>

#ifdef DEBUG
#define NSLog(args...) NSLog(@"[shadow] "args)
#else
#define NSLog(...);
#endif

#define DPKG_INFO_PATH      @"/var/lib/dpkg/info"
#define PREFS_TWEAK_ID      @"me.jjolano.shadow"
#define BLACKLIST_PATH      @"me.jjolano.shadow.blacklist"
#define APPS_PATH           @"me.jjolano.shadow.apps"
#define DLFCN_PATH          @"me.jjolano.shadow.apps.dlfcn"
#define TWEAKCOMPAT_PATH    @"me.jjolano.shadow.apps.compat.tweak"
#define LOCKDOWN_PATH       @"me.jjolano.shadow.apps.lockdown"

@interface Shadow : NSObject {
    NSMutableDictionary *link_map;
    NSMutableDictionary *path_map;
    NSMutableArray *image_set;
    NSMutableArray *url_set;
}

@property (nonatomic, assign) BOOL useTweakCompatibilityMode;
@property (nonatomic, assign) BOOL useInjectCompatibilityMode;
@property (nonatomic, assign) BOOL usePathStandardization;
@property (readonly) BOOL passthrough;

- (NSArray *)generateDyldArray;

+ (NSArray *)generateFileMap;
+ (NSArray *)generateSchemeArray;

+ (NSError *)generateFileNotFoundError;

- (BOOL)isImageRestricted:(NSString *)name;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path partial:(BOOL)partial;
- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm;
- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm partial:(BOOL)partial;
- (BOOL)isURLRestricted:(NSURL *)url;
- (BOOL)isURLRestricted:(NSURL *)url partial:(BOOL)partial;
- (BOOL)isURLRestricted:(NSURL *)url manager:(NSFileManager *)fm;
- (BOOL)isURLRestricted:(NSURL *)url manager:(NSFileManager *)fm partial:(BOOL)partial;

- (void)addPath:(NSString *)path restricted:(BOOL)restricted;
- (void)addPath:(NSString *)path restricted:(BOOL)restricted hidden:(BOOL)hidden;
- (void)addPath:(NSString *)path restricted:(BOOL)restricted hidden:(BOOL)hidden prestricted:(BOOL)prestricted phidden:(BOOL)phidden;
- (void)addRestrictedPath:(NSString *)path;
- (void)addPathsFromFileMap:(NSArray *)file_map;
- (void)addSchemesFromURLSet:(NSArray *)set;
- (void)addLinkFromPath:(NSString *)from toPath:(NSString *)to;
- (NSString *)resolveLinkInPath:(NSString *)path;

@end
