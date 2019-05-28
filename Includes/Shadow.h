#import <Foundation/Foundation.h>

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
}

@property (nonatomic, assign) BOOL useTweakCompatibilityMode;
@property (nonatomic, assign) BOOL useInjectCompatibilityMode;

+ (NSArray *)generateDyldArray;
+ (BOOL)generateFileMap;

- (BOOL)isImageRestricted:(NSString *)name;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path partial:(BOOL)partial;
- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm;
- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm partial:(BOOL)partial;
- (BOOL)isURLRestricted:(NSURL *)url;

- (void)addPath:(NSString *)path restricted:(BOOL)restricted;
- (void)addPath:(NSString *)path restricted:(BOOL)restricted hidden:(BOOL)hidden;
- (void)addPathsFromFileMap:(NSArray *)file_map;
- (void)addLinkFromPath:(NSString *)from toPath:(NSString *)to;
- (NSString *)resolveLinkInPath:(NSString *)path;

@end
