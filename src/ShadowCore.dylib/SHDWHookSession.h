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
// No-journal variant for the repair loop (RebindRepair.x): replaying a
// journaled spec must not append to the journal it is iterating, or every
// image event would grow it by the full spec count.
- (BOOL)hookRebindSymbol:(NSString*)symbolName
           withReplacement:(void*)replacement
                  outOldPtr:(void**)oldPtr
              inCallerImage:(const void*)imageHeader
                    journal:(BOOL)journal;

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

// Rebind journal + repair (anti-fishhook). Journal storage lives in
// RebindRepair.x; the slot table it pairs with lives in SHDWHookSession.m.
FOUNDATION_EXPORT void SHDWRebindJournalNote(const char* symbolName, void* replacement);
// Check-then-store repair over all journaled slots; returns repaired count.
FOUNDATION_EXPORT uint32_t SHDWRebindRepairSlots(void);
// HookKit replay of the spec journal scoped to one image header (late-loaded
// images). No-ops on a NULL session/header.
FOUNDATION_EXPORT void SHDWRebindRepairImage(SHDWHookSession* session, const void* imageHeader);
// Coalesced async repair requests (safe to call from inside hooks):
// slots-only, and slots + image replay for a fresh header.
FOUNDATION_EXPORT void SHDWRequestRebindRepair(void);
FOUNDATION_EXPORT void SHDWRequestRebindRepairImage(const void* imageHeader);
// Drop journaled slots owned by an unmapped address range, so repair never
// dereferences stale slot addresses after an image unloads.
FOUNDATION_EXPORT void SHDWRebindForgetRange(uintptr_t base, uintptr_t end);

#endif
