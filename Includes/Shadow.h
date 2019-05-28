#import <Foundation/Foundation.h>

#ifdef DEBUG
#define NSLog(args...) NSLog(@"[shadow] "args)
#else
#define NSLog(...);
#endif

#define DPKG_INFO_PATH  @"/var/lib/dpkg/info"
#define PREFS_PATH      @"/var/mobile/Library/Preferences/me.jjolano.shadow.plist"

@interface Shadow : NSObject {
    NSSet *file_map;
    NSMutableDictionary *link_map;
    NSMutableDictionary *path_map;
    NSMutableArray *dyld_array;

    BOOL passthrough;
}

@property (readonly) BOOL isDyldArrayGenerated;
@property (nonatomic) BOOL useTweakCompatibilityMode;
@property (nonatomic) BOOL useInjectCompatibilityMode;
@property (readonly) uint32_t dyldArrayCount;
@property (readonly) NSString *dyldSelfImageName;

- (void)generateDyldArray;
- (void)generateFileMap;
- (void)generateFileMapWithArray:(NSArray *)file_map_array;

- (BOOL)isImageRestricted:(NSString *)name;
- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isPathRestricted:(NSString *)path manager:(NSFileManager *)fm;
- (BOOL)isURLRestricted:(NSURL *)url;

- (void)addPath:(NSString *)path restricted:(BOOL)restricted;
- (void)addLinkFromPath:(NSString *)from toPath:(NSString *)to;
- (NSString *)resolveLinkInPath:(NSString *)path;

- (const char *)getDyldImageName:(uint32_t)image_index;

@end
