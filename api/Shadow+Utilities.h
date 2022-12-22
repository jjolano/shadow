#import <Foundation/Foundation.h>
#import "Shadow.h"

@interface Shadow (Utilities)
+ (BOOL)shouldResolvePath:(NSString *)path lstat:(void *)lstat_ptr;
+ (NSString *)getStandardizedPath:(NSString *)path;
@end
