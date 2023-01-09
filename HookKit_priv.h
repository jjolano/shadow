#import "HookKit.h"
#import <Foundation/Foundation.h>

#import "vendor/pac.h"
#import "vendor/rootless.h"

#import "vendor/libhooker/libhooker.h"
#import "vendor/libhooker/libblackjack.h"
#import "vendor/substitute/substitute.h"
#import "vendor/substrate/substrate.h"

#if __has_include("vendor/fishhook/fishhook.h")
#import "vendor/fishhook/fishhook.h"
#endif

#if __arm64__ || __arm64e__
#if __has_include("vendor/dobby/dobby.h")
#import "vendor/dobby/dobby.h"
#endif
#endif

#define PATH_LIBHOOKER      "/usr/lib/libhooker.dylib"
#define PATH_LIBBLACKJACK   "/usr/lib/libblackjack.dylib"
#define PATH_SUBSTITUTE     "/usr/lib/libsubstitute.dylib"
#define PATH_SUBSTITUTE2    "/usr/lib/libsubstitute.0.dylib"
#define PATH_SUBSTRATE      "/usr/lib/libsubstrate.dylib"
#define PATH_SUBSTRATE2     "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
#define PATH_ELLEKIT        "/usr/lib/libellekit.dylib"

@interface HKFunctionHook : NSObject
@property NSValue* function;
@property NSValue* replacement;
@property NSValue* orig;
@end

@interface HKMemoryHook : NSObject
@property NSValue* target;
@property NSValue* data;
@property NSNumber* size;
@end
