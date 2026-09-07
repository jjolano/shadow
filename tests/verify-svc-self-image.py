"""Exercise the actual raw-SVC add-image admission and initialization bodies."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ShadowCore.dylib/hooks/Universal/svc_patch.x"


def body(source: str, signature: str) -> str:
    start = source.index("{", source.index(signature))
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[source.index(signature):end]


source = SOURCE.read_text()
skip = body(source, "static BOOL shdw_svc_skip_image(")
callback = body(source, "static void shdw_svc_image_add(")
install = body(source, "void shdw_svc_patch_install(void)")

# The app-bundle exemption remains a path-policy decision. Scanner identity is
# separate and must be decided before the callback looks an image up by path.
bundle_start = skip.index("if([imagePath isEqualToString:bundlePath]")
bundle_end = skip.index("// dyld reports", bundle_start)
assert "return NO;" in skip[bundle_start:bundle_end]
assert callback.index("if(!shdw_svc_own_image || mh == shdw_svc_own_image)") < callback.index("for(uint32_t")
assert install.index("dladdr((const void*)shdw_svc_patch_install, &info)") < install.index(
    "_dyld_register_func_for_add_image"
)

prefix = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int BOOL;
#define NO 0
#define YES 1

struct mach_header { int marker; };
typedef struct { const char *dli_fname; void *dli_fbase; } Dl_info;

static const struct mach_header *shdw_svc_own_image = NULL;
static struct mach_header self_header, app_header;
static const struct mach_header *images[2];
static const char *paths[2];
static uint32_t image_count;
static int image_count_calls, registrations, patches;
static const struct mach_header *replay_header, *last_patched;
static int dladdr_ok;
static const struct mach_header *dladdr_header;

static uint32_t _dyld_image_count(void) {
    image_count_calls++;
    return image_count;
}

static const struct mach_header *_dyld_get_image_header(uint32_t index) {
    return images[index];
}

static const char *_dyld_get_image_name(uint32_t index) {
    return paths[index];
}

static BOOL shdw_svc_skip_image(const char *path) {
    return !path || strncmp(path, "/bundle/", 8) != 0;
}

static void shdw_svc_patch_image(const struct mach_header *mh, intptr_t slide,
                                 const char *path) {
    (void)slide;
    (void)path;
    patches++;
    last_patched = mh;
}

static int dladdr(const void *address, Dl_info *info) {
    (void)address;
    if(!dladdr_ok) return 0;
    info->dli_fbase = (void *)dladdr_header;
    return 1;
}

static void shdw_svc_image_add(const struct mach_header *mh, intptr_t slide);
static void _dyld_register_func_for_add_image(
    void (*callback)(const struct mach_header *, intptr_t)) {
    registrations++;
    callback(replay_header, 0);
}

static void set_image(const struct mach_header *mh, const char *path) {
    image_count = 1;
    images[0] = mh;
    paths[0] = path;
}
'''

suffix = r'''
int main(void) {
    set_image(&self_header, "/bundle/ShadowCore.dylib");
    replay_header = &self_header;

    /* Resolve failure must not register a replay callback or scan anything. */
    dladdr_ok = 0;
    shdw_svc_patch_install();
    assert(registrations == 0);
    assert(image_count_calls == 0);
    assert(patches == 0);
    assert(shdw_svc_own_image == NULL);

    /* A resolved self header is excluded before image/path admission. */
    dladdr_ok = 1;
    dladdr_header = &self_header;
    shdw_svc_patch_install();
    assert(registrations == 1);
    assert(shdw_svc_own_image == &self_header);
    assert(image_count_calls == 0);
    assert(patches == 0);

    /* Defensive callback behavior is safe even if identity becomes unavailable. */
    shdw_svc_own_image = NULL;
    shdw_svc_image_add(&self_header, 0);
    assert(image_count_calls == 0);
    assert(patches == 0);

    /* A different image beneath the app bundle remains admitted. */
    shdw_svc_own_image = &self_header;
    set_image(&app_header, "/bundle/Detector.dylib");
    shdw_svc_image_add(&app_header, 0);
    assert(image_count_calls == 1);
    assert(patches == 1);
    assert(last_patched == &app_header);

    puts("verify-svc-self-image: scanner admission assertions passed");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="shadow-svc-self-image-") as tmp:
    test = Path(tmp) / "test.c"
    executable = Path(tmp) / "test"
    test.write_text(prefix + callback + "\n\n" + install + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        str(test), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
