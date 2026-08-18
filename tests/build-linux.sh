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
  -Wall -Wno-unused-parameter -DDEBUG -O0 -g -DSHADOW_TEST_HARNESS \
  $OBJC_FLAGS \
  -include tests/hdr/dispatch/once.h -include tests/hdr/CoreFoundation/CFBundle.h \
  -Itests/hdr \
  -IShadow.framework/Headers -IShadow.framework -Itests \
  -IShadowCore.dylib/hooks \
  tests/main.m tests/ShdwPathShim.m tests/fsinterpose.c tests/ShadowFilter.m tests/ShadowdShims.m \
  tests/detectors/ShadowDetector.m tests/Fuzz.m tests/shadowd/RecoveryHarness.m \
  shadowd/ledger.m shadowd/recovery.m \
  Shadow.framework/Core.m Shadow.framework/Ruleset.m \
  Shadow.framework/Core+Utilities.m \
  Shadow.framework/DpkgRulesGenerator.m \
  Shadow.framework/RestrictionEngine.m Shadow.framework/JBPath.m \
  Shadow.framework/RulesetCompiler.m Shadow.framework/RulesetStore.m \
  tests/RestrictionTests.m tests/PolicyTests.m ShadowCore.dylib/policy/EnvironmentPolicy.m ShadowCore.dylib/policy/PseudoSandboxPolicy.m \
  Shadow.framework/HookConfiguration.m tests/CoordinatorTests.m \
  -Wl,--wrap=access -Wl,--wrap=realpath -Wl,--wrap=open \
  $BASE_LIBS -o tests/harness

echo "built tests/harness"
