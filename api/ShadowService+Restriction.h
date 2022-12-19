#import <Foundation/Foundation.h>
#import "ShadowService.h"

@interface ShadowService (Restriction)
+ (BOOL)isPathRestricted_db:(NSArray *)db withPath:(NSString *)path;
+ (BOOL)isPathRestricted_dpkg:(NSString *)dpkgPath withPath:(NSString *)path;
+ (NSArray *)getURLSchemes_db:(NSSet *)db;
+ (NSArray *)getURLSchemes_dpkg:(NSString *)dpkgPath;
@end
