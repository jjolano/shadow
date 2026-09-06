// ObjC-visible face of EmbeddedDrivers.swift (theos generates no Swift
// bridging header for app targets, so declare the interface by hand).
// Nullability is spelled out: the toolchain builds with -Werror and
// Apple's headers default to audited regions here.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SHDWEmbeddedSwift : NSObject
+ (nullable NSDictionary *)runDetector:(NSString *)identifier;
@end

static inline NSDictionary * _Nullable SHDWEmbeddedSwiftRunDetector(NSString *identifier) {
    return [SHDWEmbeddedSwift runDetector:identifier];
}

// TalsecBridge (harness's own TalsecBridge.swift, already linked).
@interface TalsecBridge : NSObject
+ (void)start;
+ (NSArray<NSString *> *)threats;
+ (BOOL)allChecksFinished;
@end

NS_ASSUME_NONNULL_END
