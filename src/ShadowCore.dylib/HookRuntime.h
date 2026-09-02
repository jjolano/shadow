#ifndef shadow_hook_runtime_h
#define shadow_hook_runtime_h

#import <Shadow.h>
#import <stdint.h>

// Hot hook paths share one cached, immortal Shadow singleton. Store the
// pointer as an integer because this toolchain rejects atomic ObjC pointers
// under ARC.
static inline Shadow* shdw_shadow_instance(void) {
    static uintptr_t instance = 0;
    Shadow* cached = (__bridge Shadow *)(void *) __atomic_load_n(&instance, __ATOMIC_ACQUIRE);

    if(!cached) {
        cached = [Shadow sharedInstance];
        __atomic_store_n(&instance, (uintptr_t)(__bridge void *) cached, __ATOMIC_RELEASE);
    }

    return cached;
}

#define _shadow shdw_shadow_instance()

#endif
