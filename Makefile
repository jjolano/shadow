ARCHS ?= armv7 armv7s arm64 arm64e
# TARGET: clang:latest keeps the toolchain current; the 9.0 floor matches
# control's Depends: firmware (>= 9.0) and lets one fat package serve armv7
# through arm64e, the way 1.0.x shipped. Note: theos bumps the arm64e slice
# minos to 14.0 automatically, so the low floor costs the modern slices
# nothing. The rootless pass overrides both (see build.sh).
TARGET ?= iphone:clang:latest:9.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = HKSubstitutor.m vendor/fishhook/fishhook.c vendor/litehook/litehook.c
# Native backend: arm64/arm64e only, stubbed out by #if on armv7.
HookKit_FILES += native/hk_native.c native/hk_arm64.c native/hk_symbols.c
# Swift vtable backend: arm64/arm64e only (entry points report unsupported on
# armv7 via hk_swift_supported()).
HookKit_FILES += native/hk_swift.c
HookKit_FRAMEWORKS = Foundation
# RootBridge is the /var/jb convention; roothide replaces it with libroothide
# via the HKJBPath seam in HKSubstitutor.m.
ifneq ($(THEOS_PACKAGE_SCHEME),roothide)
HookKit_EXTRA_FRAMEWORKS = RootBridge
endif
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_PUBLIC_HEADERS = Headers/HookKit.h Headers/HookKit
HookKit_CFLAGS = -fobjc-arc -IHeaders -Ivendor -Ivendor/litehook
ifneq ($(THEOS_PACKAGE_SCHEME),roothide)
HookKit_CFLAGS += -Ivendor/RootBridge.framework/Headers
else
HookKit_CFLAGS += -DSHADOW_ROOTHIDE
endif
HookKit_LDFLAGS = -Fvendor
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

include $(THEOS_MAKE_PATH)/framework.mk

# Dobby: vendored static lib, arm64/arm64e slices only (no armv7), C++
# implementation so it needs libc++ at link. Excluded from the legacy
# armv7/armv7s build by the ARCHS filter.
ifeq ($(filter arm64,$(ARCHS)),arm64)
HookKit_LDFLAGS += -Lvendor/dobby -ldobby -lc++
endif

# HKGum: thin wrapper dylib statically linking the frida-gum devkit. The
# framework never links gum — the Frida backend dlopens HKGum.dylib at
# runtime via RootBridge (see HKSubstitutor.m), keeping LGPL code out of the
# framework binary. The devkit ships no armv7 slice, so this product is pinned
# to arm64/arm64e per-product rather than gated on the global ARCHS: that lets
# the framework span all four slices in one pass while gum stays 64-bit.
# Rootless packaging maps /usr/lib -> /var/jb/usr/lib automatically.
LIBRARY_NAME = HKGum
HKGum_FILES = vendor/gum/hkgum.c
HKGum_ARCHS = arm64 arm64e
HKGum_LDFLAGS = -Lvendor/gum -lfrida-gum
HKGum_INSTALL_PATH = /usr/lib
include $(THEOS_MAKE_PATH)/library.mk

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
