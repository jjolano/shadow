#!/bin/sh
# Builds the harness with the GNUstep toolchain (libobjc2 + clang). Runs
# inside the gnustep/base container, from the repo root (see tests/Makefile).
# Pass --coverage to instrument the engine sources for gcov.
set -e

COV_FLAGS=
if [ "$1" = "--coverage" ]; then
    COV_FLAGS="--coverage"
fi

OBJC_FLAGS=$(gnustep-config --objc-flags)
BASE_LIBS=$(gnustep-config --base-libs)

# -Wl,--wrap=access/-Wl,--wrap=realpath/-Wl,--wrap=open arm the virtual
# filesystem and shadow filter (fsinterpose.c): every access()/realpath()/
# open() call in the binary routes literal /var/jb paths into the fixture
# tree and consults the engine before answering.
clang -fobjc-arc -fobjc-runtime=gnustep-2.0 -fblocks $COV_FLAGS \
  -Wall -Wno-unused-parameter -DDEBUG -O0 -g \
  $OBJC_FLAGS \
  -include tests/hdr/dispatch/once.h -include tests/hdr/CoreFoundation/CFBundle.h \
  -Itests/hdr \
  -IShadow.framework/Headers -IShadow.framework -Ivendor/RootBridge.framework/Headers \
  tests/main.m tests/RootBridgeStub.m tests/fsinterpose.c tests/ShadowFilter.m \
  tests/detectors/ShadowDetector.m \
  Shadow.framework/Core.m Shadow.framework/Backend.m Shadow.framework/Ruleset.m \
  Shadow.framework/Core+Utilities.m \
  -Wl,--wrap=access -Wl,--wrap=realpath -Wl,--wrap=open \
  $BASE_LIBS -o tests/harness

echo "built tests/harness"
