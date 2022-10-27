#import "hooks.h"

%group shadowhook_dyld
%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *result = %orig(image_index);

    if(result) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:result length:strlen(result)];

        if([_shadow isPathRestricted:image_name]) {
            return %orig(0);
        }
    }

    return result;
}
%end

void shadowhook_dyld(void) {
    %init(shadowhook_dyld);
}
