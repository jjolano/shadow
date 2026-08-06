#ifndef shadow_backend_h
#define shadow_backend_h

#import <Foundation/Foundation.h>
#import <Shadow/Ruleset.h>

__attribute__((visibility("default")))
@interface ShadowBackend : NSObject {
    NSArray<RulesetEngine *>* rulesets;
    NSCache<NSString *, NSNumber *>* cache_restricted;
    double rulesetDirMtime;
    NSArray<NSNumber *>* rulesetFileMtimes;
}

- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isSchemeRestricted:(NSString *)scheme;
@end
#endif
