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

FOUNDATION_EXPORT SHDWHookSession* SHDWHookSessionSetCurrent(SHDWHookSession* session);
FOUNDATION_EXPORT void SHDWHookMessage(Class objcClass, SEL selector,
                                       IMP replacement, IMP* original);

#endif
