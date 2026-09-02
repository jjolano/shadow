#ifndef shadow_path_rewrite_h
#define shadow_path_rewrite_h

#include <stddef.h>

// Offset of the byte to munge in a NUL-terminated path string, or
// (size_t)-1 when there is nothing safe to munge (empty string, trailing
// slash). The munged byte flips the middle of the FINAL path component to
// 0x01 (a control char that no real jailbreak-detection target is named
// with), so any lookup of the rewritten string fails with ENOENT while the
// string keeps its exact length — the rewrite is strictly in place, no
// reallocation, no truncation to a different (real) path.
size_t shdw_path_munge_offset(const char *path);

// Applies the munge in place. Returns 1 when a byte was flipped, 0 when the
// path had nothing safe to munge.
int shdw_path_munge_path(char *path);

// True when the page containing `ptr` is writable (vm_region query). Used
// before munging so a read-only buffer (e.g. a __TEXT string constant) falls
// back to the synthetic deny instead of crashing. Mach-only; the pure munge
// functions above compile anywhere.
int shdw_path_buf_writable(const char *ptr);

#endif /* shadow_path_rewrite_h */