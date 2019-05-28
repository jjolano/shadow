#include <mach-o/dyld.h>

%hookf(uint32_t, _dyld_image_count) {
    if([_shadow isDyldArrayGenerated]) {
        return [_shadow dyldArrayCount];
    }

    return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    if([_shadow isDyldArrayGenerated]) {
        // Use generated dyld array.
        return [_shadow getDyldImageName:image_index];
    }

    // Basic filter.
    const char *ret = %orig;

    if(ret && [_shadow isImageRestricted:[NSString stringWithUTF8String:ret]]) {
        return [[_shadow dyldSelfImageName] UTF8String];
    }

    return ret;
}
/*
%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    if(generated_dyld_array) {
        // Use generated dyld array.
        if(image_index >= dyld_clean_array_count) {
            return NULL;
        }

        image_index = [dyld_clean_array[image_index] unsignedIntegerValue];
    }

    return %orig(image_index);
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    if(generated_dyld_array) {
        // Use generated dyld array.
        if(image_index >= dyld_clean_array_count) {
            return 0;
        }

        image_index = [dyld_clean_array[image_index] unsignedIntegerValue];
    }

    return %orig(image_index);
}
*/
