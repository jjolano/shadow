#ifndef shadow_core_utilities_h
#define shadow_core_utilities_h

#import "Core.h"
#import <Foundation/Foundation.h>

// Root aliases the ruleset vocabulary treats as one path. Input must already
// be slash/dot-normalized and have no trailing slash (except "/" itself).
static inline NSString *SHDWPathApplyingRootAliases(NSString *path) {
  if ([path isEqualToString:@"/private/var"] ||
      [path hasPrefix:@"/private/var/"]) {
    path = [path substringFromIndex:8];
  }
  if ([path isEqualToString:@"/private/etc"] ||
      [path hasPrefix:@"/private/etc/"]) {
    path = [path substringFromIndex:8];
  }
  // After the /private/var rewrite, /private/var/tmp is /var/tmp.
  if ([path isEqualToString:@"/var/tmp"] || [path hasPrefix:@"/var/tmp/"]) {
    path = [path substringFromIndex:4];
  }
  return path;
}

@interface Shadow (Utilities)
+ (NSString *)getStandardizedPath:(NSString *)path;
+ (NSString *)getExecutablePath;
+ (NSString *)getBundleIdentifier;
+ (NSArray *)filterPathArray:(NSArray *)array
                  restricted:(BOOL)restricted
                     options:(NSDictionary<NSString *, id> *)options;

// C0-3: Cocoa error factory for the file layer. Produces NSCocoaErrorDomain
// errors with the standard file userInfo keys (NSFilePathErrorKey, and
// NSURLErrorKey when a URL is given) so every Foundation file hook reports
// the same stock-looking error shape.
+ (NSError *)fileErrorWithCode:(NSInteger)code
                          path:(NSString *)path
                           url:(NSURL *)url;
+ (NSError *)fileNoSuchFileErrorForPath:(NSString *)path;
+ (NSError *)fileNoSuchFileErrorForURL:(NSURL *)url;
@end
#endif
