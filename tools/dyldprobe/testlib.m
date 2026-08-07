// shdwtestlib — a tiny, dedicated, unloadable dylib for dyldprobe's
// add/remove-image stress (main.m section 6). On-disk (never in the dyld
// shared cache, so dlclose can fully unload it) and free of static state
// that could pin the image. The probe dlopens a container copy of this
// dylib and expects it present in the direct dyld_all_image_infos read
// while loaded and gone after dlclose.

int shdwtestlib_probe_marker(void) {
    return 0x5D0C;
}
