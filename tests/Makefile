# Host test harness for Shadow's decision engine (no device required).

# Pure-C check for the svc path-munging logic (path_rewrite.c — no
# Foundation, so it compiles and runs on any host, macOS or Linux).
verify-path-rewrite:
	$(CC) -std=c99 -Wall -Wextra -o /tmp/opencode/rewrite-test \
		verify-path-rewrite.c ../ShadowCore.dylib/hooks/FileHiding/path_rewrite.c
	/tmp/opencode/rewrite-test

verify-device-driver:
	python3 stealth_device.py selftest
	./stealth-device.sh selftest

# Builds the real Shadow.framework decision sources against a host Foundation
# with a path shim.
# Nothing here touches the theos/device toolchain.
#
# Platform split:
#   macOS   — clang + the system Foundation; `make` builds `harness`.
#   Linux   — the official GNUstep container (gnustep/base: clang +
#             libobjc2 + GNUstep Foundation). `make` builds and runs through
#             docker; the binary lands in tests/harness.

# HookKit headers for the harness come from the Theos install (HookKit repo:
# make install-theos), staged into vendor/ (gitignored, arch-independent) since
# neither this harness nor the container carries Theos. build.sh no longer
# stages them, so the harness provisions its own.
THEOS ?= /opt/theos
HOOKKIT_HEADERS ?= $(THEOS)/lib/HookKit.framework/Headers

stage-hookkit-headers:
	@test -d "$(HOOKKIT_HEADERS)" || { echo "no HookKit headers at $(HOOKKIT_HEADERS) — set HOOKKIT_HEADERS or run 'make install-theos' in the HookKit repo" >&2; exit 1; }
	rm -rf ../vendor/HookKit.framework/Headers
	mkdir -p ../vendor/HookKit.framework
	cp -R "$(HOOKKIT_HEADERS)" ../vendor/HookKit.framework/Headers

UNAME := $(shell uname)

ifeq ($(UNAME),Darwin)

CC ?= clang
FRAMEWORK = ../Shadow.framework
VENDOR = ../vendor

CFLAGS = -fobjc-arc -Wall -Wno-unused-parameter -DDEBUG -O0 -g -DSHADOW_TEST_HARNESS
INCS = -I$(FRAMEWORK)/Headers -I$(FRAMEWORK) -I. -I../ShadowCore.dylib/hooks \
       -I$(VENDOR)/HookKit.framework/Headers

SRCS = main.m ShdwPathShim.m fsinterpose.c ShadowFilter.m detectors/ShadowDetector.m Fuzz.m \
       $(FRAMEWORK)/Core.m \
       $(FRAMEWORK)/Ruleset.m \
       $(FRAMEWORK)/Core+Utilities.m \
       $(FRAMEWORK)/DpkgRulesGenerator.m \
       $(FRAMEWORK)/RestrictionEngine.m \
       $(FRAMEWORK)/JBPath.m \
       $(FRAMEWORK)/RulesetCompiler.m \
       $(FRAMEWORK)/RulesetStore.m \
       RestrictionTests.m \
       PolicyTests.m ../ShadowCore.dylib/policy/EnvironmentPolicy.m \
       ../ShadowCore.dylib/policy/PseudoSandboxPolicy.m \
       $(FRAMEWORK)/HookConfiguration.m \
       CoordinatorTests.m \
       VersionCompareTests.m HookFallbackTests.c

harness: $(SRCS) Makefile | stage-hookkit-headers
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

harness: image stage-hookkit-headers
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

.PHONY: stage-hookkit-headers test test-rooted detect adversary adversary-rooted detector benign shipped fuzz afuzz coverage clean verify-path-rewrite verify-device-driver
