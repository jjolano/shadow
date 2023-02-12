#import <Foundation/Foundation.h>
#import "Shadow.h"

@interface Shadow (Utilities)
+ (NSString *)getStandardizedPath:(NSString *)path;
+ (NSString *)getExecutablePath;
+ (NSString *)getBundleIdentifier;
@end
