"""Pin the two hook decisions that caused the app-launch crashes.

Both fixes are behavioural decisions living inside Logos-preprocessed .x
sources, so this extracts the real function bodies (and the constants they
depend on) and drives them on the host with synthetic inputs:

  * shdw_svc_site_needs_stub     -- which redirected svc sites need a per-site
    continuation stub (a site that resumes at site+4 must not be reached with
    BL, whose return address would clobber the enclosing function's live x30)
    gets. Picking BL for a frameless leaf destroys x30, turning the leaf's own
    `ret` into a self-loop (My Sun Life, 0x8BADF00D, pc == lr).
  * shdw_image_span_ex           -- the vm span recorded for one image. A union
    over all segments stretches a shared-cache image across its whole subcache,
    so every later stock image reads as restricted and dlsym returns NULL for
    stock symbols (GasBuddy/Oxford kSec*, CBC News swift_task_escalate).

The span cases below use the shapes measured on the device, including the
liblzma.5.dylib one that produced an 848 MB span before the fix.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SVC = ROOT / "src/ShadowCore.dylib/hooks/Universal/svc_patch.x"
DYLD = ROOT / "src/ShadowCore.dylib/hooks/Universal/dyld.x"


def anchor_pattern(needle):
    """Regex for `needle`, tolerant of reformat spacing (see verify-svc-self-image)."""
    return r"\s*".join(
        re.escape(tok) for tok in re.findall(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]", needle)
    )


def anchor(text, needle, start=0):
    match = re.search(anchor_pattern(needle), text[start:])
    if match is None:
        raise ValueError(f"anchor not found: {needle!r}")
    return start + match.start()


def body(source, signature):
    """Brace-matched body (signature included) of one function."""
    head = anchor(source, signature)
    start = anchor(source, "{", head)
    depth, end = 1, start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[head:end]


def define(source, name):
    """The full text of `#define <name> ...`, so the test uses the real value."""
    match = re.search(rf"^#define\s+{re.escape(name)}\s+(.*)$", source, re.M)
    if match is None:
        raise ValueError(f"#define {name} not found")
    return match.group(0)


svc_src = SVC.read_text()
dyld_src = DYLD.read_text()

stub_fn = body(svc_src, "static BOOL shdw_svc_site_needs_stub(")
span_fn = body(dyld_src, "static BOOL shdw_image_span_ex(")
rebuild_fn = body(dyld_src, "static void shdw_restricted_ranges_full_rebuild(")
note_add_fn = body(dyld_src, "void shdw_restricted_ranges_note_add(")


def check_source_pins():
    """The span callers must refuse to answer when a restricted image has no
    computable span.

    Gating that on the oversized flag alone left any *unreadable* header
    silently absent from a table that still published as authoritative — a
    definitive "not restricted" for the image's whole address range (the
    armv7/armv7s lane, before `shdw_image_span_ex` learned MH_MAGIC).
    """
    for label, fn in (("shdw_restricted_ranges_full_rebuild", rebuild_fn),
                      ("shdw_restricted_ranges_note_add", note_add_fn)):
        assert fn.strip(), f"{label}: extracted body is empty"
        compact = "".join(fn.split())
        at = compact.find("shdw_image_span_ex(")
        assert at != -1, f"{label}: no image span call"
        assert "if(oversized)" not in compact, (
            f"{label}: the unanswerable marking must not be gated on the "
            f"oversized flag alone")
        tail = compact[at:at + 900]
        stops = [i for i in (tail.find("continue;"), tail.find("return;"))
                 if i != -1]
        cut = min(stops) if stops else len(tail)
        assert "overflowed=1;" in tail[:cut], (
            f"{label}: a restricted image without a computable span must mark "
            f"the published table unanswerable")

# The extracted bodies reference these; take them from the sources verbatim so a
# changed constant is a test failure rather than a silently stale expectation.
svc_defines = "\n".join(
    define(svc_src, n) for n in ("SHDW_SVC_RET", "SHDW_SVC_B", "SHDW_SVC_BL")
)
span_defines = define(dyld_src, "SHDW_SPAN_MAX_BYTES")

HARNESS = """
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef int BOOL;
#define YES 1
#define NO 0
#define MH_MAGIC 0xfeedface
#define MH_MAGIC_64 0xfeedfacf
#define LC_SEGMENT 0x1
#define LC_SEGMENT_64 0x19

struct load_command { uint32_t cmd; uint32_t cmdsize; };
struct segment_command_64 {
    uint32_t cmd; uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr; uint64_t vmsize;
    uint64_t fileoff; uint64_t filesize;
    uint32_t maxprot; uint32_t initprot; uint32_t nsects; uint32_t flags;
};
/* The 32-bit shapes the rootful-legacy (armv7/armv7s) lane ships. Real sizes
   matter here: the extracted body selects the header size and the segment
   layout from the magic, so a fake 32-byte `struct mach_header` would move the
   load-command walk off the real 28-byte offset and the armv7 case below would
   pass for the wrong reason. */
struct segment_command {
    uint32_t cmd; uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr; uint32_t vmsize;
    uint32_t fileoff; uint32_t filesize;
    uint32_t maxprot; uint32_t initprot; uint32_t nsects; uint32_t flags;
};
struct mach_header {
    uint32_t magic; uint32_t cputype; uint32_t cpusubtype; uint32_t filetype;
    uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags;
};
struct mach_header_64 {
    uint32_t magic; uint32_t cputype; uint32_t cpusubtype; uint32_t filetype;
    uint32_t ncmds; uint32_t sizeofcmds; uint32_t flags; uint32_t reserved;
};

/* Constants lifted from the production sources. */
__SVC_DEFINES__
__SPAN_DEFINES__

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; \\
    printf("FAIL: "); printf(__VA_ARGS__); printf("\\n"); } } while (0)

/* ---- extracted production logic ---- */
__SPAN_FN__

__BRANCH_FN__

typedef struct { const char* name; uint64_t vmaddr; uint64_t vmsize; } seg_spec_t;

static struct mach_header* make_image(const seg_spec_t* segs, int n) {
    size_t need = sizeof(struct mach_header_64) +
                  (size_t)n * sizeof(struct segment_command_64);
    char* buf = (char*)calloc(1, need);
    struct mach_header* mh = (struct mach_header*)buf;
    mh->magic = MH_MAGIC_64;
    mh->ncmds = (uint32_t)n;
    mh->sizeofcmds = (uint32_t)(n * sizeof(struct segment_command_64));
    struct segment_command_64* sc =
        (struct segment_command_64*)(buf + sizeof(struct mach_header_64));
    for (int i = 0; i < n; i++) {
        size_t len = strlen(segs[i].name);
        if (len > 15) len = 15;
        sc[i].cmd = LC_SEGMENT_64;
        sc[i].cmdsize = sizeof(struct segment_command_64);
        memcpy(sc[i].segname, segs[i].name, len);
        sc[i].vmaddr = segs[i].vmaddr;
        sc[i].vmsize = segs[i].vmsize;
    }
    return mh;
}

/* 32-bit (armv7/armv7s) counterpart: 28-byte header, 32-bit segment fields. */
static struct mach_header* make_image32(const seg_spec_t* segs, int n) {
    size_t need = sizeof(struct mach_header) +
                  (size_t)n * sizeof(struct segment_command);
    char* buf = (char*)calloc(1, need);
    struct mach_header* mh = (struct mach_header*)buf;
    mh->magic = MH_MAGIC;
    mh->ncmds = (uint32_t)n;
    mh->sizeofcmds = (uint32_t)(n * sizeof(struct segment_command));
    struct segment_command* sc =
        (struct segment_command*)(buf + sizeof(struct mach_header));
    for (int i = 0; i < n; i++) {
        size_t len = strlen(segs[i].name);
        if (len > 15) len = 15;
        sc[i].cmd = LC_SEGMENT;
        sc[i].cmdsize = sizeof(struct segment_command);
        memcpy(sc[i].segname, segs[i].name, len);
        sc[i].vmaddr = (uint32_t)segs[i].vmaddr;
        sc[i].vmsize = (uint32_t)segs[i].vmsize;
    }
    return mh;
}

int main(void) {
    uintptr_t base = 0, end = 0;
    BOOL oversized = NO, ok = NO;

    /* ---- svc site routing ---- */
    /* `svc; ret` returns through the x30 it saw, so the shared trampoline can
       be reached with B and its own ret lands where the app's ret would. */
    CHECK(shdw_svc_site_needs_stub(SHDW_SVC_RET) == NO,
          "svc;ret leaf must use the shared trampoline, got stub=%d",
          shdw_svc_site_needs_stub(SHDW_SVC_RET));
    /* Any other fallthrough resumes at site+4, which BL buys by destroying
       x30 — live in a leaf that continues after the svc (svc;cset;...;ret).
       Those sites must be reached with B into a stub that preserves x30;
       entering one with BL spins in the enclosing epilogue on device. */
    CHECK(shdw_svc_site_needs_stub(0x91000000U) == YES,
          "a site that resumes at site+4 must go through a stub, got stub=%d",
          shdw_svc_site_needs_stub(0x91000000U));

    /* ---- image span ---- */

    /* Ordinary image: page-adjacent segments, span covers the whole run. */
    const seg_spec_t normal[] = {
        { "__TEXT",     0x100000000ULL, 0x8000 },
        { "__DATA",     0x100008000ULL, 0x4000 },
        { "__LINKEDIT", 0x10000c000ULL, 0x2000 },
    };
    struct mach_header* mh = make_image(normal, 3);
    oversized = NO;
    CHECK(shdw_image_span_ex(mh, 0, &base, &end, &oversized) == YES,
          "ordinary image must yield a span");
    CHECK(base == 0x100000000ULL && end == 0x10000e000ULL,
          "ordinary span must cover the contiguous run, got %#llx-%#llx",
          (unsigned long long)base, (unsigned long long)end);
    CHECK(oversized == NO, "ordinary image must not be flagged oversized");
    free(mh);

    /* __PAGEZERO is not mapped and must not seed the run. */
    const seg_spec_t pagezero[] = {
        { "__PAGEZERO", 0x0ULL,         0x100000000ULL },
        { "__TEXT",     0x100000000ULL, 0x8000 },
    };
    mh = make_image(pagezero, 2);
    oversized = NO;
    CHECK(shdw_image_span_ex(mh, 0, &base, &end, &oversized) == YES,
          "__PAGEZERO must not suppress the span");
    CHECK(base == 0x100000000ULL && end == 0x100008000ULL,
          "__PAGEZERO must be excluded, got %#llx-%#llx",
          (unsigned long long)base, (unsigned long long)end);
    free(mh);

    /* The regression: a shared-cache image whose segments sit in different
       subcache regions. Measured on device as /usr/lib/liblzma.5.dylib with
       __TEXT 0x19000, a far __DATA_CONST, and __LINKEDIT reporting the whole
       subcache's link-edit region. A union over these produced an 848 MB span
       covering Security.framework and libswift_Concurrency. */
    const seg_spec_t cached[] = {
        { "__TEXT",       0x1db26c000ULL, 0x19000 },
        { "__DATA_CONST", 0x1f36b2fc8ULL, 0x368 },
        { "__LINKEDIT",   0x1ff644000ULL, 0xb9e0be3 },
    };
    mh = make_image(cached, 3);
    oversized = NO;
    ok = shdw_image_span_ex(mh, 0, &base, &end, &oversized);
    CHECK(!(ok == YES && (end - base) > 0x10000000ULL),
          "shared-cache image must not span the subcache, got %#llx-%#llx (%llu bytes)",
          (unsigned long long)base, (unsigned long long)end,
          (unsigned long long)(end - base));
    CHECK(ok == YES && base == 0x1db26c000ULL && end == 0x1db285000ULL,
          "shared-cache span must be just the __TEXT run, got %#llx-%#llx",
          (unsigned long long)base, (unsigned long long)end);
    free(mh);

    /* A span past the bound must be refused AND reported, so the caller marks
       the table unanswerable instead of recording a range that may cover
       unrelated images. */
    const seg_spec_t huge[] = {
        { "__TEXT",     0x100000000ULL, 0x1000 },
        { "__LINKEDIT", 0x100001000ULL, (uint64_t)SHDW_SPAN_MAX_BYTES },
    };
    mh = make_image(huge, 2);
    oversized = NO;
    ok = shdw_image_span_ex(mh, 0, &base, &end, &oversized);
    CHECK(ok == NO && oversized == YES,
          "oversized span must be refused and reported (ok=%d oversized=%d)",
          ok, oversized);
    free(mh);

    /* 32-bit armv7/armv7s image (rootful-legacy lane): must yield a span. The
       old 64-bit-only magic gate refused every 32-bit header, which published
       an empty-but-authoritative restricted-image table on that lane (every
       address answered "not restricted") and left the rebind journal's unload
       prune without a range. Slide is applied the same way as the 64-bit case. */
    const seg_spec_t legacy[] = {
        { "__TEXT",     0x4000, 0x8000 },
        { "__DATA",     0xc000, 0x4000 },
        { "__LINKEDIT", 0x10000, 0x2000 },
    };
    mh = make_image32(legacy, 3);
    oversized = NO;
    CHECK(shdw_image_span_ex(mh, 0, &base, &end, &oversized) == YES,
          "32-bit (armv7) image must yield a span");
    CHECK(base == 0x4000ULL && end == 0x12000ULL,
          "32-bit span must cover the contiguous run, got %#llx-%#llx",
          (unsigned long long)base, (unsigned long long)end);
    CHECK(oversized == NO, "32-bit image must not be flagged oversized");
    CHECK(shdw_image_span_ex(mh, 0x1000, &base, &end, &oversized) == YES &&
              base == 0x5000ULL && end == 0x13000ULL,
          "32-bit span must apply the slide, got %#llx-%#llx",
          (unsigned long long)base, (unsigned long long)end);
    free(mh);

    /* A 32-bit __PAGEZERO (4 GB reserved but unmapped on armv7) must not seed
       the run either. */
    const seg_spec_t legacy_pagezero[] = {
        { "__PAGEZERO", 0x0ULL, 0x4000 },
        { "__TEXT",     0x4000, 0x8000 },
    };
    mh = make_image32(legacy_pagezero, 2);
    oversized = NO;
    CHECK(shdw_image_span_ex(mh, 0, &base, &end, &oversized) == YES &&
              base == 0x4000ULL && end == 0xc000ULL,
          "32-bit __PAGEZERO must be excluded, got %#llx-%#llx",
          (unsigned long long)base, (unsigned long long)end);
    free(mh);

    /* Malformed image: refused, not guessed. */
    const seg_spec_t one[] = { { "__TEXT", 0x1000ULL, 0x1000 } };
    mh = make_image(one, 1);
    mh->magic = 0;
    oversized = NO;
    CHECK(shdw_image_span_ex(mh, 0, &base, &end, &oversized) == NO,
          "wrong magic must be refused");
    free(mh);

    /* More segments than the run buffer holds: refused and reported, never
       silently truncated. A dropped segment would shorten the span, which
       reads as "not restricted" -- the unsafe direction. */
    {
        enum { MANY = 40 };
        seg_spec_t many[MANY];
        char names[MANY][16];
        for (int i = 0; i < MANY; i++) {
            snprintf(names[i], sizeof(names[i]), "__SEG%d", i);
            many[i].name = names[i];
            many[i].vmaddr = 0x200000000ULL + (uint64_t)i * 0x1000;
            many[i].vmsize = 0x1000;
        }
        mh = make_image(many, MANY);
        oversized = NO;
        ok = shdw_image_span_ex(mh, 0, &base, &end, &oversized);
        CHECK(ok == NO && oversized == YES,
              "over-long segment list must be refused and reported (ok=%d oversized=%d)",
              ok, oversized);
        free(mh);
    }

    if (failures) { printf("%d assertion(s) failed\\n", failures); return 1; }
    printf("image span + svc branch: all assertions passed\\n");
    return 0;
}
"""


def build_source():
    source = HARNESS.replace("__SPAN_FN__", span_fn)
    source = source.replace("__BRANCH_FN__", stub_fn)
    source = source.replace("__SVC_DEFINES__", svc_defines)
    source = source.replace("__SPAN_DEFINES__", span_defines)
    return source


def run():
    try:
        check_source_pins()
    except AssertionError as exc:
        print(f"image span source pin: FAIL: {exc}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        c = Path(tmp) / "span_branch.c"
        exe = Path(tmp) / "span_branch"
        c.write_text(build_source())
        compiled = subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c99", "-Wall", "-Wextra",
             "-Werror", "-o", str(exe), str(c)],
            capture_output=True, text=True)
        if compiled.returncode != 0:
            sys.stderr.write(compiled.stderr)
            return 1
        result = subprocess.run([str(exe)], capture_output=True, text=True)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode


if __name__ == "__main__":
    sys.exit(run())
