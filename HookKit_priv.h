#import <Foundation/Foundation.h>

#import "vendor/rootless.h"

#import "vendor/libhooker/libhooker.h"
#import "vendor/libhooker/libblackjack.h"
#import "vendor/substitute/substitute.h"
#import "vendor/substrate/substrate.h"

#if __has_include("vendor/fishhook/fishhook.h")
#import "vendor/fishhook/fishhook.h"
#endif

@interface HKFunctionHook : NSObject
@property void * function;
@property void * replacement;
@property void ** orig;
@end

@interface HKMemoryHook : NSObject
@property void * target;
@property const void * data;
@property size_t size;
@end
