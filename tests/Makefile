# Host test harness for Shadow's decision engine (no device required).

# Builds the REAL Shadow.framework decision sources (Core.m, Backend.m,
# Ruleset.m, Core+Utilities.m) against a host Foundation with a stubbed
# RootBridge. Nothing here touches the theos/device toolchain.
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

CFLAGS = -fobjc-arc -Wall -Wno-unused-parameter -DDEBUG -O0 -g
INCS = -I$(FRAMEWORK)/Headers -I$(FRAMEWORK) -I$(VENDOR)/RootBridge.framework/Headers

SRCS = main.m RootBridgeStub.m fsinterpose.c ShadowFilter.m detectors/ShadowDetector.m Fuzz.m \
       $(FRAMEWORK)/Core.m \
       $(FRAMEWORK)/Backend.m \
       $(FRAMEWORK)/Ruleset.m \
       $(FRAMEWORK)/Core+Utilities.m

harness: $(SRCS) Makefile
	$(CC) $(CFLAGS) $(INCS) $(SRCS) -framework Foundation -o harness

test: harness
	./harness

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

detector: harness
	$(RUN) tests/harness --detector

detect: harness
	$(RUN) tests/harness --detect

benign: harness
	$(RUN) tests/harness --benign

fuzz: harness
	$(RUN) tests/harness --fuzz

# CI fuzz-smoke: known D4 transient class is allowed (reported, not fatal).
afuzz: harness
	$(RUN) tests/harness --afuzz

fuzz-smoke: harness
	$(RUN) env SHADW_FUZZ_ALLOW_D4=1 tests/harness --fuzz

adversary: harness
	$(RUN) tests/harness --adversary

coverage: image
	$(RUN) sh /src/tests/coverage-report.sh

clean:
	rm -f harness harness.d

endif

.PHONY: test detect adversary detector benign fuzz coverage clean
