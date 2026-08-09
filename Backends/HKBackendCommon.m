#import "Internal/HKBackendInternal.h"

#import <dlfcn.h>
#import <mach-o/dyld.h>

// The @implementation lives here (not the shared header): the ivars of
// HKHookOperation are @public and referenced from every backend TU through
// the _OBJC_IVAR_$_ symbols, which only the implementing TU emits.
@implementation HKHookOperation
@end

// Jailbreak-root path seam — same convention as Shadow's JBPath.h. Legacy
// rootless/rooted resolve via RootBridge (/var/jb); roothide has no /var/jb
// (random-named jbroot) so it uses libroothide's jbroot() instead.
#ifdef SHADOW_ROOTHIDE
#import <roothide.h>
NSString* HKJBPath(NSString* path) { return jbroot(path); }
#else
#import <RootBridge.h>
NSString* HKJBPath(NSString* path) { return [RootBridge getJBPath:path]; }
#endif

// Shared by every backend that scans for a symbol with no image specified.
void *hk_search_loaded_images(void *(^probe)(const char *imageName)) {
    int count = _dyld_image_count();

    for(int i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);

        if(!image_name) {
            continue;
        }

        void *found = probe(image_name);

        if(found) {
            return found;
        }
    }

    return NULL;
}

hookkit_status_t hk_batch_status(int succeeded, int total) {
    if(succeeded < total) {
        NSLog(@"[HookKit] warning: successfully hooked less than expected (%d/%d)", succeeded, total);
    }

    if(succeeded == total) {
        return HK_OK;
    }

    return succeeded > 0 ? HK_ERR_PARTIAL : HK_ERR;
}

// Shared dlfcn image lookup for the backends whose engines bring no image API
// of their own (fishhook, Dobby, Frida) — the three had byte-identical copies.
// Deliberately not <HKSubstitutorBackend>-conforming: that would warn on the
// six hooking methods it has no business implementing. Subclasses declare the
// protocol themselves.
// ponytail: the native backend has this same shape over hk_native_open_image/
// _find_symbol/_close_image; parameterising open/find/close as ivars to absorb
// it costs more lines than the copy does. Revisit if a fifth copy appears.
// Declared here, not just defined below: -Wprotocol resolves a subclass's
// conformance against declared methods, so the inherited trio must be visible
// at the subclass @interface.
@implementation HKDlfcnBackend

- (HKImageRef)openImage:(NSString *)path {
    // RTLD_NOLOAD: inspect-only, never loads the dylib — matches the MS/ElleKit
    // contract that openImage does not load images
    return (HKImageRef)dlopen([path fileSystemRepresentation], RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
}

- (void)closeImage:(HKImageRef)image {
    if(image) {
        dlclose((void *)image);
    }
}

- (void *)findSymbolInImage:(HKImageRef)image symbolName:(NSString *)symbolName {
    const char *symbol = [symbolName UTF8String];

    if(image) {
        return dlsym((void *)image, symbol);
    }

    // image == NULL: search the default scope, then all loaded dyld images
    void *found = dlsym(RTLD_DEFAULT, symbol);

    if(found) {
        return found;
    }

    return hk_search_loaded_images(^void *(const char *image_name) {
        void *handle = dlopen(image_name, RTLD_LAZY | RTLD_NOLOAD);

        if(!handle) {
            return NULL;
        }

        void *result = dlsym(handle, symbol);
        dlclose(handle);
        return result;
    });
}
@end