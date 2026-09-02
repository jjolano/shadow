#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>

#import "identity_fixture.h"

int shdw_identity_fixture_probe(const char* bundleID, const char* scheme,
                                shdw_identity_fixture_result_t* result) {
    if(!result) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->version = 1;
    result->bundle_proxy_present = -1;
    result->scheme_result_count = -1;
    result->caller_address = (uintptr_t)&shdw_identity_fixture_probe;

    struct stat st;
    errno = 0;
    result->stat_result = stat("/var/jb", &st);
    result->stat_errno = errno;
    result->dyld_image_count = _dyld_image_count();
    result->objc_shadow_present = objc_getClass("Shadow") ? 1 : 0;
    result->dyld_insert_present = getenv("DYLD_INSERT_LIBRARIES") ? 1 : 0;

    (void)dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY | RTLD_LOCAL);

    @autoreleasepool {
        NSString* bundle = bundleID ? [NSString stringWithUTF8String:bundleID] : nil;
        NSString* urlScheme = scheme ? [NSString stringWithUTF8String:scheme] : nil;
        Class proxyClass = objc_getClass("LSApplicationProxy");
        SEL proxySelector = sel_registerName("applicationProxyForIdentifier:");

        @try {
            if(bundle && proxyClass && class_getClassMethod(proxyClass, proxySelector)) {
                typedef id (*ProxyMessage)(id, SEL, id);
                result->bundle_proxy_present = ((ProxyMessage)objc_msgSend)((id)proxyClass, proxySelector, bundle) ? 1 : 0;
            }

            Class workspaceClass = objc_getClass("LSApplicationWorkspace");
            SEL workspaceSelector = sel_registerName("defaultWorkspace");
            SEL schemeSelector = sel_registerName("applicationsAvailableForHandlingURLScheme:");

            if(urlScheme && workspaceClass && class_getClassMethod(workspaceClass, workspaceSelector)) {
                typedef id (*WorkspaceMessage)(id, SEL);
                id workspace = ((WorkspaceMessage)objc_msgSend)((id)workspaceClass, workspaceSelector);

                if(workspace && [workspace respondsToSelector:schemeSelector]) {
                    typedef id (*SchemeMessage)(id, SEL, id);
                    id values = ((SchemeMessage)objc_msgSend)(workspace, schemeSelector, urlScheme);
                    result->scheme_result_count = values ? (int32_t)[values count] : -1;
                }
            }
        } @catch(NSException* exception) {
            (void)exception;
        }
    }

    return 0;
}
