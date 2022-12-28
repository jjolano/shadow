#import "HookKit.h"
#import <Foundation/Foundation.h>

#import "vendor/rootless.h"

#import "vendor/libhooker/libhooker.h"
#import "vendor/libhooker/libblackjack.h"
#import "vendor/substitute/substitute.h"
#import "vendor/substrate/substrate.h"

#if __has_include("vendor/fishhook/fishhook.h")
#import "vendor/fishhook/fishhook.h"
#endif

#ifndef __arm64e__
#ifdef __arm64__
#if __has_include("vendor/dobby/dobby.h")
#import "vendor/dobby/dobby.h"
#endif
#endif
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

#define PATH_LIBHOOKER      "/usr/lib/libhooker.dylib"
#define PATH_LIBBLACKJACK   "/usr/lib/libblackjack.dylib"
#define PATH_SUBSTITUTE     "/usr/lib/libsubstitute.dylib"
#define PATH_SUBSTRATE      "/usr/lib/libsubstrate.dylib"
