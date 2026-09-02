#ifndef shdw_hook_session_h
#define shdw_hook_session_h

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

typedef NSString* SHDWImageRef;

// Shadow's only HookKit boundary. Each request uses the native HK3 lifecycle;
// keeping it here avoids leaking HK3 request structs through every hook file.
@interface SHDWHookSession : NSObject

- (BOOL)hookMessageInClass:(Class)objcClass
              withSelector:(SEL)selector
           withReplacement:(void*)replacement
                  outOldPtr:(void**)oldPtr;
- (BOOL)hookFunction:(void*)function
      withReplacement:(void*)replacement
             outOldPtr:(void**)oldPtr;
- (BOOL)hookRebindSymbol:(NSString*)symbolName
          withReplacement:(void*)replacement
                 outOldPtr:(void**)oldPtr;
- (BOOL)hookRebindSymbol:(NSString*)symbolName
          withReplacement:(void*)replacement
                 outOldPtr:(void**)oldPtr
             inCallerImage:(const void*)imageHeader;

- (SHDWImageRef)openImage:(NSString*)path;
- (void)closeImage:(SHDWImageRef)image;
- (void*)findSymbolInImage:(SHDWImageRef)image symbolName:(NSString*)symbolName;

@end

// Restrict this process's function/memory hooks to one HookKit backend engine
// ID (from the HK_Library pref). "auto"/NULL/empty clears the override. Set once
// at ShadowCore init, before hooks run. A strict override that cleanly refuses
// a function/memory hook retries automatic routing once; partial or unknown
// mutation never retries. The pinned HookKit exports the backend-override
// constructor, so this is live by default; ShadowCore resolves it dynamically
// because the hookkit dependency floor is only >= 3.0.0 and the package version
// does not bump across the export — against an older installed build the
// override is skipped and automatic routing stands.
FOUNDATION_EXPORT void SHDWSetProcessBackendOverride(const char* backendID);

// Map a hooked-method replacement/current IMP back to its original IMP, so a
// dladdr() on the hooked IMP can resolve to the genuine (system) image instead
// of ShadowCore. Returns NULL when the address is not a recorded hook IMP.
FOUNDATION_EXPORT const void* SHDWOriginalIMPForReplacement(const void* address);
// Record a hooked replacement/current IMP -> original mapping for the dladdr
// swizzle-origin filter (used by satellites that capture originals directly).
FOUNDATION_EXPORT void SHDWRememberHookedIMPRemap(const void* replacement, const void* original);
// Snapshot an instance method IMP before a %hook, then register the
// replacement->original mapping after, so a detector's dladdr on the hooked IMP
// resolves to the original's (system) image.
FOUNDATION_EXPORT void* SHDWSnapshotInstanceMethodIMP(Class cls, SEL sel);
FOUNDATION_EXPORT void SHDWRegisterHookedInstanceMethod(Class cls, SEL sel, void* originalIMP);

FOUNDATION_EXPORT SHDWHookSession* SHDWHookSessionSetCurrent(SHDWHookSession* session);
FOUNDATION_EXPORT void SHDWHookMessage(Class objcClass, SEL selector,
                                       IMP replacement, IMP* original);
FOUNDATION_EXPORT IMP SHDWOriginalImplementationForMethod(Method method);
FOUNDATION_EXPORT BOOL SHDWRangeOverlapsProtectedImportSlots(uintptr_t address,
                                                              size_t size);

#endif
