ARCHS ?= armv7 armv7s arm64 arm64e
# TARGET: clang:latest keeps the toolchain current; the 9.0 floor matches
# control's Depends: firmware (>= 9.0) and lets one fat package serve armv7
# through arm64e, the way 1.0.x shipped. Note: theos bumps the arm64e slice
# minos to 14.0 automatically, so the low floor costs the modern slices
# nothing. The rootless pass overrides both (see build.sh).
TARGET ?= iphone:clang:latest:9.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = HKSubstitutor.m HKBackendRegistry.m Backends/HKBackendCommon.m Backends/HKElleKitBackend.m Backends/HKMSBackends.m Backends/HKFishhookBackend.m Backends/HKLitehookBackend.m Backends/HKInlineBackends.m Backends/HKNativeBackends.m vendor/fishhook/fishhook.c vendor/litehook/litehook.c Internal/HKSubstituteErrors.c Internal/HKInlinePreflight.m
# Native backend: arm64/arm64e only, stubbed out by #if on armv7.
HookKit_FILES += native/hk_native.c native/hk_arm64.c native/hk_symbols.c
# Swift vtable backend: arm64/arm64e only (entry points report unsupported on
# armv7 via hk_swift_supported()).
HookKit_FILES += native/hk_swift.c
HookKit_FRAMEWORKS = Foundation
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_PUBLIC_HEADERS = Headers/HookKit.h Headers/HookKit
HookKit_CFLAGS = -fobjc-arc -I. -IHeaders -Ivendor -Ivendor/litehook
HookKit_LDFLAGS =
# Jailbreak-root seam is compile-time per scheme (see Backends/HKBackendCommon.m):
# rooted = identity, rootless = libroot (auto-linked -lroot by theos),
# roothide = libroothide's jbroot(). Must append after the base CFLAGS above.
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
HookKit_CFLAGS += -DSHADOW_ROOTLESS
else ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
HookKit_CFLAGS += -DSHADOW_ROOTHIDE
endif
# The roothide scheme module forces -install_name "@loader_path/.jbroot...",
# which would override our @rpath install_name (instance LDFLAGS come after
# internal LDFLAGS); under the roothide scheme drop our explicit install_name
# so the module's .jbroot one wins.
ifneq ($(THEOS_PACKAGE_SCHEME),roothide)
HookKit_LDFLAGS += -install_name @rpath/HookKit.framework/HookKit
else
HookKit_LDFLAGS += -lroothide
endif
HookKit_LDFLAGS += -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
# Mach-O dylib versions: must match HookKit.tbd (current/compatibility 2.1.1)
# so consumers linking via the tbd record a satisfiable requirement. Theos
# sets no versions itself, so they come from here.
HookKit_LDFLAGS += -current_version 2.1.1 -compatibility_version 2.1.1
# Export boundary: only the public HKSubstitutor ObjC class symbols survive
# the link (see scripts/export-HookKit.list); every backend/litehook/dobby/
# fishhook/native symbol becomes local.
HookKit_LDFLAGS += -exported_symbols_list $(CURDIR)/scripts/export-HookKit.list

include $(THEOS_MAKE_PATH)/framework.mk

# Dobby: vendored static lib, arm64/arm64e slices only (no armv7), C++
# implementation so it needs libc++ at link. Excluded from the legacy
# armv7/armv7s build by the ARCHS filter.
ifeq ($(filter arm64,$(ARCHS)),arm64)
HookKit_LDFLAGS += -Lvendor/dobby -ldobby -lc++
endif

# HKGum: thin wrapper dylib statically linking the frida-gum devkit. The
# framework never links gum — the Frida backend dlopens HKGum.dylib at
# runtime via RootBridge (see Backends/HKInlineBackends.m), keeping LGPL code
# out of the framework binary. The devkit ships no armv7 slice, so this
# product is pinned to arm64/arm64e per-product rather than gated on the
# global ARCHS: that lets the framework span all four slices in one pass while
# gum stays 64-bit. Rootless packaging maps /usr/lib -> /var/jb/usr/lib
# automatically.
LIBRARY_NAME = HKGum
HKGum_FILES = vendor/gum/hkgum.c
HKGum_ARCHS = arm64 arm64e
# Export boundary: only the 3 hkgum_* wrappers (scripts/export-HKGum.list);
# the ~6k frida-gum symbols become local.
HKGum_LDFLAGS = -Lvendor/gum -lfrida-gum -exported_symbols_list $(CURDIR)/scripts/export-HKGum.list
HKGum_INSTALL_PATH = /usr/lib
include $(THEOS_MAKE_PATH)/library.mk

# Release export check: verifies every built binary exports exactly its
# allowlist (scripts/export-*.list), per arch slice. Discovers the freshly
# built products under .theos (fat + per-arch thin copies + staged copies),
# so it works after both `make` and `make package`. Fails with a clear
# diff-style message on any discrepancy.
.PHONY: check-exports
check-exports:
	$(ECHO_NOTHING)bash scripts/check_exports.sh$(ECHO_END)

# Host-side test aggregate: builds and runs both suites in sequence, stopping
# at the first failure (no -k).
.PHONY: test
test:
	$(ECHO_NOTHING)$(MAKE) test-reloc test-swift-abi test-substitute-classifier$(ECHO_END)

# Host-side relocator test. Runs on the build machine, not the device: it only
# exercises instruction decode/re-encode, which is where the crashes come from.
.PHONY: test-reloc
test-reloc:
	$(ECHO_NOTHING)mkdir -p $(THEOS_OBJ_DIR) && clang -Wall -Wextra -O2 -o $(THEOS_OBJ_DIR)/test_arm64_reloc tests/test_arm64_reloc.c native/hk_arm64.c && $(THEOS_OBJ_DIR)/test_arm64_reloc$(ECHO_END)

# Host-side Swift vtable engine test. The test includes native/hk_swift.c
# itself so it can inject a simulated pointer-authentication scheme (the host
# has no PAC hardware) and a fake hk_native_patch_memory, then drives the
# engine's core against a hand-built fake class metadata blob. -rdynamic puts
# the test's fake method symbols into .dynsym so dladdr resolves them, which
# is what lets the name-matching paths run on the host.
.PHONY: test-swift-abi
test-swift-abi:
	$(ECHO_NOTHING)mkdir -p $(THEOS_OBJ_DIR) && clang -Wall -Wextra -O2 -rdynamic -o $(THEOS_OBJ_DIR)/test_swift_abi tests/test_swift_abi.c && $(THEOS_OBJ_DIR)/test_swift_abi$(ECHO_END)

# Host-side substitute error classifier test. Pure code table, runs on the
# build machine. Compiles as ObjC so the test can include the REAL
# Headers/HookKit/Compat.h and the REAL vendored substitute.h (through a fake
# __APPLE__ plus minimal Mach-O/ObjC/Foundation header stubs, so the vendored
# header's Apple-only sections compile on Linux). The classifier under test is
# the REAL Internal/HKSubstituteErrors.c — compiled alongside the test, no
# mirror copy. The -I$(CURDIR)/Internal flag is needed for the helper's
# include of "HKSubstituteErrors.h" from the test's compilation directory.
.PHONY: test-substitute-classifier
test-substitute-classifier:
	$(ECHO_NOTHING)mkdir -p $(THEOS_OBJ_DIR) && clang -Wall -Wextra -O2 -x objective-c -Ivendor -IHeaders -I$(CURDIR)/tests/fake_headers -I$(CURDIR)/Internal -D__APPLE__ -o $(THEOS_OBJ_DIR)/test_substitute_classifier tests/test_substitute_classifier.c Internal/HKSubstituteErrors.c && $(THEOS_OBJ_DIR)/test_substitute_classifier$(ECHO_END)
