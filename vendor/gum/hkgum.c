// Thin C wrapper around the frida-gum devkit. HookKit's framework never links
// gum directly; the HKGumBackend dlopens this dylib at runtime via RootBridge,
// which keeps the 38MB lib out of the framework and keeps the LGPL-2.1
// (wxWindows exception) boundary clean: this file is the only LGPL-derived
// code, and it is built as a separate dylib.
//
// provenance: frida 17.17.0 frida-gum devkit, LGPL-2.1 wxWindows exception,
// source https://github.com/frida/frida-gum
#include "frida-gum.h"

__attribute__((constructor)) static void hkgum_ctor(void) { gum_init_embedded(); }

int hkgum_hook_function(void *address, void *replacement, void **out_original) {
    return gum_interceptor_replace(gum_interceptor_obtain(), address, replacement, out_original, NULL);
}   // returns GumReplaceReturn; 0 == GUM_REPLACE_OK
int hkgum_begin_transaction(void) { gum_interceptor_begin_transaction(gum_interceptor_obtain()); return 0; }
int hkgum_end_transaction(void)   { gum_interceptor_end_transaction(gum_interceptor_obtain());   return 0; }
