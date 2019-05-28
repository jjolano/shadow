#include <dlfcn.h>

%hookf(void *, dlsym, void *handle, const char *symbol) {
    if(!symbol) {
        return %orig;
    }

    NSString *sym = [NSString stringWithUTF8String:symbol];

    if([sym hasPrefix:@"MS"] /* Substrate */
    || [sym hasPrefix:@"Sub"] /* Substitute */
    || [sym hasPrefix:@"PS"] /* Substitrate */) {
        return NULL;
    }

    return %orig;
}