#ifndef shadow_backend_h
#define shadow_backend_h

#import <Foundation/Foundation.h>
#import <Shadow/Ruleset.h>

@interface ShadowBackend : NSObject {
    NSArray<ShadowRuleset *>* rulesets;
    NSCache<NSString *, NSNumber *>* cache_restricted;
}

- (BOOL)isPathRestricted:(NSString *)path;
- (BOOL)isSchemeRestricted:(NSString *)scheme;
@end
#endif
