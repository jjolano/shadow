#ifndef shadow_core_utilities_h
#define shadow_core_utilities_h

#import <Foundation/Foundation.h>
#import "Core.h"

@interface Shadow (Utilities)
+ (NSString *)getStandardizedPath:(NSString *)path;
+ (NSString *)getExecutablePath;
+ (NSString *)getBundleIdentifier;
+ (NSArray *)filterPathArray:(NSArray *)array restricted:(BOOL)restricted options:(NSDictionary<NSString *, id> *)options;

// C0-3: Cocoa error factory for the file layer. Produces NSCocoaErrorDomain
// errors with the standard file userInfo keys (NSFilePathErrorKey, and
// NSURLErrorKey when a URL is given) so every Foundation file hook reports
// the same stock-looking error shape.
+ (NSError *)fileErrorWithCode:(NSInteger)code path:(NSString *)path url:(NSURL *)url;
+ (NSError *)fileNoSuchFileErrorForPath:(NSString *)path;
+ (NSError *)fileNoSuchFileErrorForURL:(NSURL *)url;
@end
#endif
