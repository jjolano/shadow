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

FOUNDATION_EXPORT SHDWHookSession* SHDWHookSessionSetCurrent(SHDWHookSession* session);
FOUNDATION_EXPORT void SHDWHookMessage(Class objcClass, SEL selector,
                                       IMP replacement, IMP* original);
FOUNDATION_EXPORT IMP SHDWOriginalImplementationForMethod(Method method);
FOUNDATION_EXPORT BOOL SHDWRangeOverlapsProtectedImportSlots(uintptr_t address,
                                                              size_t size);

#endif
