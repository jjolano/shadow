// Virtual-filesystem and dyld-symbol shims for the harness (see fsinterpose.c).

#ifndef shdw_fsinterpose_h
#define shdw_fsinterpose_h

#ifdef __cplusplus
extern "C" {
#endif

// Installs the fixture jbroot backing the virtual filesystem; NULL/empty
// disables mapping (rooted mode). Linux-only effect.
void shdw_fs_set_jbroot(const char* jbroot);

// Installs the argv backing the _NSGetArgv() provider. Linux-only effect.
void shdw_fs_set_argv(char** argv);

// Enables/disables the shadow-active filter: while enabled, the wrapped
// access()/open()/realpath() calls hide engine-restricted paths (ENOENT for
// reads, EACCES for writes), exactly like the device hook layer. Linux-only
// effect; implemented in fsinterpose.c + ShadowFilter.m.
void shdw_shadow_filter_set_enabled(int enabled);

#ifdef __cplusplus
}
#endif

#endif
