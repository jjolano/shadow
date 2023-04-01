#ifndef shadow_core_utilities_h
#define shadow_core_utilities_h

#import <Foundation/Foundation.h>
#import "Core.h"

@interface Shadow (Utilities)
+ (NSString *)getStandardizedPath:(NSString *)path;
+ (NSString *)getExecutablePath;
+ (NSString *)getBundleIdentifier;
+ (NSDictionary *)generateDatabase;
+ (NSArray *)filterPathArray:(NSArray *)array restricted:(BOOL)restricted options:(NSDictionary<NSString *, id> *)options;
@end
#endif
