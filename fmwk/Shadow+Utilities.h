#import <Foundation/Foundation.h>
#import "Shadow.h"

@interface Shadow (Utilities)
+ (BOOL)shouldResolvePath:(NSString *)path;
+ (NSString *)getStandardizedPath:(NSString *)path;
@end
