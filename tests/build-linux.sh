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
  -Isrc/Shadow.framework/Headers -Isrc/Shadow.framework -Itests \
  -Ivendor/HookKit.framework/Headers \
  -Isrc/ShadowCore.dylib/hooks -Isrc/ShadowCore.dylib/hooks/Universal \
  tests/main.m tests/ShdwPathShim.m tests/fsinterpose.c tests/ShadowFilter.m \
  tests/detectors/ShadowDetector.m tests/Fuzz.m \
  src/Shadow.framework/Core.m src/Shadow.framework/Ruleset.m \
  src/Shadow.framework/Core+Utilities.m \
  src/Shadow.framework/DpkgRulesGenerator.m \
  src/Shadow.framework/RestrictionEngine.m src/Shadow.framework/JBPath.m \
  src/Shadow.framework/RulesetCompiler.m src/Shadow.framework/RulesetStore.m \
  tests/RestrictionTests.m tests/PolicyTests.m src/ShadowCore.dylib/policy/EnvironmentPolicy.m \
  src/Shadow.framework/HookConfiguration.m src/Shadow.framework/SettingsMigration.m src/ShadowCore.dylib/HookAdapterBridge.m tests/CoordinatorTests.m \
  tests/VersionCompareTests.m tests/HookFallbackTests.c \
  -Wl,--export-dynamic \
  -Wl,--wrap=access -Wl,--wrap=realpath -Wl,--wrap=open \
  $BASE_LIBS -o tests/harness

echo "built tests/harness"
