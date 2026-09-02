#ifndef shadow_restriction_query_h
#define shadow_restriction_query_h

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, ShadowRestrictionOperation) {
    ShadowRestrictionOperationRead = 0,
    ShadowRestrictionOperationWrite = 1
};

typedef NS_OPTIONS(NSUInteger, ShadowRestrictionFlags) {
    ShadowRestrictionFlagResolve = 1 << 0,
    ShadowRestrictionFlagNoFollow = 1 << 1
};

__attribute__((visibility("hidden")))
@interface ShadowRestrictionQuery : NSObject
@property (copy, nonatomic) NSString* path;
@property (copy, nonatomic) NSString* workingDirectory;
@property (assign, nonatomic) ShadowRestrictionOperation operation;
@property (assign, nonatomic) ShadowRestrictionFlags flags;
+ (instancetype)queryWithPath:(NSString *)path;
@end

#endif
