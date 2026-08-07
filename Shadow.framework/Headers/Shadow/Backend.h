#ifndef shadow_backend_h
#define shadow_backend_h

#import <Foundation/Foundation.h>
#import <Shadow/Ruleset.h>

__attribute__((visibility("default")))
@interface ShadowBackend : NSObject {
    NSArray<RulesetEngine *>* rulesets;
    NSCache<NSString *, NSArray *>* cache_restricted;
    double rulesetDirMtime;
    NSArray<NSNumber *>* rulesetFileMtimes;
    NSUInteger rulesetGeneration;
}

- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isSchemeRestricted:(NSString *)scheme;
- (BOOL)isBundleIDRestricted:(NSString *)bundleID;
@end
#endif
