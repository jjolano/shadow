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
#define INJECTCOMPAT_PATH   @"me.jjolano.shadow.apps.compat.injection"
#define LOCKDOWN_PATH       @"me.jjolano.shadow.apps.lockdown"

@interface NSTask : NSObject

@property (copy) NSArray *arguments;
@property (copy) NSString *currentDirectoryPath;
@property (copy) NSDictionary *environment;
@property (copy) NSString *launchPath;
@property (readonly) int processIdentifier;
@property (retain) id standardError;
@property (retain) id standardInput;
@property (retain) id standardOutput;

+ (id)currentTaskDictionary;
+ (id)launchedTaskWithDictionary:(id)arg1;
+ (id)launchedTaskWithLaunchPath:(id)arg1 arguments:(id)arg2;

- (id)init;
- (void)interrupt;
- (bool)isRunning;
- (void)launch;
- (bool)resume;
- (bool)suspend;
- (void)terminate;

@end

@interface Shadow : NSObject {
    NSMutableDictionary *link_map;
    NSMutableDictionary *path_map;
    NSMutableArray *url_set;
}

@property (nonatomic, assign) BOOL useTweakCompatibilityMode;
@property (nonatomic, assign) BOOL useInjectCompatibilityMode;
@property (readonly) BOOL passthrough;

- (NSArray *)generateDyldArray;

+ (NSArray *)generateFileMap;
+ (NSArray *)generateSchemeArray;

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
