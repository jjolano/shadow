// shdwtestlib — a C-only, dynamically unloadable dylib for dyldprobe's
// add/remove-image stress.  Keep it free of Objective-C runtime/framework
// dependencies so its sole dlopen reference can reach zero at dlclose.

int shdwtestlib_probe_marker(void) {
    return 0x5D0C;
}
