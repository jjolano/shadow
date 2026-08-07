# Shadow harness toolchain image: clang + libobjc2 + GNUstep base.
#
# Ubuntu's apt GNUstep stack is built against GCC's libobjc4, which does not
# support ARC. The harness (and the Shadow framework sources) are ARC code,
# so this image builds the GNUstep runtime (libobjc2) and base library from
# source against clang — the standard ARC-capable GNUstep toolchain.
#
# Build once:   docker build -t shadow-harness tests/
# Used by:      tests/Makefile (Linux branch)

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential clang cmake ninja-build pkg-config git ca-certificates \
        libffi-dev libxml2-dev libgnutls28-dev libicu-dev zlib1g-dev uuid-dev \
        libclang-rt-18-dev llvm-18 \
    && rm -rf /var/lib/apt/lists/*

# GNUstep runtime (ARC-capable). Pinned to the v2.2.1 release (matches the
# classic GNUstep ABI era of gnustep-base 1.29). The base image's GCC
# toolchain ships a libobjc dev symlink in its own directory; ld searches
# GCC dirs before system dirs, so -lobjc binds to GCC's legacy runtime (no
# blocks/ARC support) instead of libobjc2. That silently breaks
# gnustep-base's runtime probes (blocks check fails -> legacy ObjectiveC2
# glue gets built -> vendored-vs-installed header conflicts). Drop the stale
# symlink so -lobjc always resolves to libobjc2.
RUN git clone --depth 1 --branch v2.2.1 https://github.com/gnustep/libobjc2.git /tmp/libobjc2 \
    && mkdir -p /tmp/libobjc2/build \
    && cd /tmp/libobjc2/build \
    && cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
             -DCMAKE_INSTALL_PREFIX=/usr .. \
    && ninja && ninja install \
    && ldconfig \
    && rm -f /usr/lib/gcc/x86_64-linux-gnu/*/libobjc.so /usr/lib/gcc/x86_64-linux-gnu/*/libobjc.a \
    && rm -rf /tmp/libobjc2

# gnustep-make configured for clang + libobjc2 (the apt package is
# GCC-configured and would select the wrong runtime ABI)
RUN git clone --depth 1 https://github.com/gnustep/tools-make.git /tmp/gnustep-make \
    && cd /tmp/gnustep-make \
    && ./configure --with-layout=fhs CC=clang \
    && make install \
    && rm -rf /tmp/gnustep-make

# GNUstep base (Foundation, CoreFoundation compat). The rm is repeated here
# (not only in the libobjc2 step) so this step is self-sufficient: if the
# base image's GCC libobjc dev symlink survives, -lobjc binds to the legacy
# runtime, configure's blocks probe fails, the legacy ObjectiveC2 glue gets
# built, and the vendored-vs-installed runtime headers conflict.
#
# The sed fixes -contentsOfDirectoryAtURL:includingPropertiesForKeys:
# options:error: building child URLs from the enumerator's RELATIVE names
# with plain +fileURLWithPath: (resolved against the process CWD — every
# ruleset URL was garbage in the harness). The engine relies on this method
# to enumerate the rulesets dir.
#
# The patch implements NSPredicate NSCoding (encodeWithCoder/initWithCoder
# were subclassResponsibility FIXMEs): the archive format-string round-trip
# is semantically equivalent, and without it Shadow's compiled-cache write
# (Ruleset.m _writeCompiledCacheForRuleset) throws mid-encode; GNUstep's
# NSKeyedArchiver then over-releases in dealloc and corrupts the heap.
# Bare NSExpression archiving is still unsupported (never produced by the
# engine's cache payloads).
COPY patches/gnustep-1.29-predicate-coding.patch /tmp/
RUN git clone --depth 1 --branch base-1_29_0 https://github.com/gnustep/libs-base.git /tmp/gnustep-base \
    && rm -f /usr/lib/gcc/x86_64-linux-gnu/*/libobjc.so /usr/lib/gcc/x86_64-linux-gnu/*/libobjc.a \
    && cd /tmp/gnustep-base \
    && sed -i 's|tempURL = \[NSURL fileURLWithPath: tempPath\];|tempURL = [NSURL fileURLWithPath: tempPath relativeToURL: url];|' Source/NSFileManager.m \
    && patch -p1 --ignore-whitespace < /tmp/gnustep-1.29-predicate-coding.patch \
    && ./configure --with-layout=fhs \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /tmp/gnustep-base

WORKDIR /src
