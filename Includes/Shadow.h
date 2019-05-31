#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>

#ifdef DEBUG
#define NSLog(args...) NSLog(@"[shadow] "args)
#else
#define NSLog(...);
#endif

#define DPKG_INFO_PATH  @"/var/lib/dpkg/info"
#define PREFS_PATH      @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"

@interface Shadow : NSObject {
    NSMutableDictionary *link_map;
    NSMutableDictionary *path_map;

    BOOL passthrough;
    char *rpath;
}

@property (nonatomic, assign) BOOL useTweakCompatibilityMode;
@property (nonatomic, assign) BOOL useInjectCompatibilityMode;

- (NSMutableArray *)generateDyldNameArray;
- (struct mach_header *)generateDyldHeaderArray;
- (intptr_t *)generateDyldSlideArray;
+ (NSArray *)generateFileMap;

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
- (void)addRestrictedPath:(NSString *)path;
- (void)addPathsFromFileMap:(NSArray *)file_map;
- (void)addLinkFromPath:(NSString *)from toPath:(NSString *)to;
- (NSString *)resolveLinkInPath:(NSString *)path;

@end
