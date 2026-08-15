# Host test harness for Shadow's decision engine (no device required).

# Builds the real Shadow.framework decision sources against a host Foundation
# with a path shim.
# Nothing here touches the theos/device toolchain.
#
# Platform split:
#   macOS   — clang + the system Foundation; `make` builds `harness`.
#   Linux   — the official GNUstep container (gnustep/base: clang +
#             libobjc2 + GNUstep Foundation). `make` builds and runs through
#             docker; the binary lands in tests/harness.

UNAME := $(shell uname)

ifeq ($(UNAME),Darwin)

CC ?= clang
FRAMEWORK = ../Shadow.framework
VENDOR = ../vendor

CFLAGS = -fobjc-arc -Wall -Wno-unused-parameter -DDEBUG -O0 -g -DSHADOW_TEST_HARNESS
INCS = -I$(FRAMEWORK)/Headers -I$(FRAMEWORK) -I. -I../ShadowCore.dylib/hooks

SRCS = main.m ShdwPathShim.m fsinterpose.c ShadowFilter.m ShadowdShims.m detectors/ShadowDetector.m Fuzz.m \
       shadowd/RecoveryHarness.m \
       ../shadowd/ledger.m \
       ../shadowd/recovery.m \
       $(FRAMEWORK)/Core.m \
       $(FRAMEWORK)/Ruleset.m \
       $(FRAMEWORK)/Core+Utilities.m \
       $(FRAMEWORK)/DpkgRulesGenerator.m \
       $(FRAMEWORK)/RestrictionEngine.m \
       $(FRAMEWORK)/RulesetCompiler.m \
       $(FRAMEWORK)/RulesetStore.m \
       RestrictionTests.m \
       PolicyTests.m ../ShadowCore.dylib/policy/EnvironmentPolicy.m \
       $(FRAMEWORK)/HookConfiguration.m \
       CoordinatorTests.m

harness: $(SRCS) Makefile
	$(CC) $(CFLAGS) $(INCS) $(SRCS) -framework Foundation -o harness

test: harness
	./harness

# Rooted-only runs for platforms without the virtual FS (macOS): the
# rootless assertions depend on the Linux interposer.
test-rooted: harness
	./harness --rooted

adversary-rooted: harness
	./harness --rooted --adversary

detector: harness
	./harness --detector

detect: harness
	./harness --detect

benign: harness
	./harness --benign

fuzz: harness
	./harness --fuzz

adversary: harness
	./harness --adversary

clean:
	rm -f harness harness.d

else

DOCKER ?= docker
IMAGE := shadow-harness:latest
RUN := $(DOCKER) run --rm -v $(CURDIR)/..:/src -w /src $(IMAGE)

image:
	$(DOCKER) build -t $(IMAGE) $(CURDIR)

harness: image
	$(RUN) sh /src/tests/build-linux.sh

test: harness
	$(RUN) tests/harness

# Rooted-only runs for platforms without the virtual FS (macOS): the
# rootless assertions depend on the Linux interposer.
test-rooted: harness
	$(RUN) tests/harness --rooted

adversary-rooted: harness
	$(RUN) tests/harness --rooted --adversary

detector: harness
	$(RUN) tests/harness --detector

detect: harness
	$(RUN) tests/harness --detect

benign: harness
	$(RUN) tests/harness --benign

fuzz: harness
	$(RUN) tests/harness --fuzz

shipped: harness
	$(RUN) tests/harness --shipped

afuzz: harness
	$(RUN) tests/harness --afuzz

adversary: harness
	$(RUN) tests/harness --adversary

coverage: image
	$(RUN) sh /src/tests/coverage-report.sh

clean:
	rm -f harness harness.d

endif

.PHONY: test test-rooted detect adversary adversary-rooted detector benign shipped fuzz afuzz coverage clean
