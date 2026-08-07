#ifndef rootbridge_h
#define rootbridge_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RootBridge : NSObject

/*!
 * @brief Detect whether this framework is installed on a rootless jailbreak.
 *
 * Detection is based on where RootBridge itself is installed: a /Library or
 * /usr prefix means rooted, anything else means rootless. The result is the
 * same for every caller in the process and is computed once.
 *
 * @return YES on a rootless jailbreak. Defaults to YES when the image path
 *         cannot be determined (conservative: prefers /var/jb paths).
 */
+ (BOOL)isJBRootless;

/*!
 * @brief Rewrite a jailbreak path for a rootless platform.
 *
 * Maps /Library/... to /var/jb/Library/... and /usr/... to /var/jb/usr/...
 * when running rootless. Every other path is returned unchanged, including
 * already-rootless paths (/var/jb/...), non-jailbreak paths such as
 * /var/mobile/..., and relative paths. Returns the path unchanged on rooted
 * platforms.
 *
 * @param path The jailbreak path to rewrite.
 * @return The rootless variant of the path when needed, otherwise the
 *         original path.
 */
+ (nullable NSString *)getJBPath:(nullable NSString *)path;

@end

NS_ASSUME_NONNULL_END

#endif
