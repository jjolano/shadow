#import "HookAdapterBridge.h"

#import <stdatomic.h>

static _Atomic(uintptr_t) gPathPredicate = 0;
static _Atomic(uintptr_t) gDladdrRemapper = 0;
static _Atomic(uintptr_t) gCanOpenURLOriginal = 0;
static _Atomic(uintptr_t) gCanOpenURLReplacement = 0;
void SHDWSetAdapterPathPredicate(SHDWAdapterPathPredicate predicate) {
    atomic_store_explicit(&gPathPredicate, (uintptr_t)predicate, memory_order_release);
}

BOOL SHDWAdapterPathIsHidden(NSString* path) {
    SHDWAdapterPathPredicate predicate = (SHDWAdapterPathPredicate)atomic_load_explicit(&gPathPredicate, memory_order_acquire);
    return predicate && predicate(path);
}

void SHDWSetDladdrRemapper(SHDWDladdrRemapper remapper) {
    atomic_store_explicit(&gDladdrRemapper, (uintptr_t)remapper, memory_order_release);
}

const void* SHDWRemapDladdrAddress(const void* address, const void* caller) {
    SHDWDladdrRemapper remapper = (SHDWDladdrRemapper)atomic_load_explicit(&gDladdrRemapper, memory_order_acquire);
    return remapper ? remapper(address, caller) : NULL;
}

void SHDWPublishCanOpenURLArtifacts(void* original, void* replacement) {
    atomic_store_explicit(&gCanOpenURLOriginal, (uintptr_t)original, memory_order_release);
    atomic_store_explicit(&gCanOpenURLReplacement, (uintptr_t)replacement, memory_order_release);
}

void* SHDWCanOpenURLOriginal(void) {
    return (void*)atomic_load_explicit(&gCanOpenURLOriginal, memory_order_acquire);
}

void* SHDWCanOpenURLReplacement(void) {
    return (void*)atomic_load_explicit(&gCanOpenURLReplacement, memory_order_acquire);
}
