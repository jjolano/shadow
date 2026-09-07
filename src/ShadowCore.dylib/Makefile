INSTALL_TARGET_PROCESSES = SpringBoard

include ../../build-support/build-lanes.mk
include $(THEOS)/makefiles/common.mk
include ../../build-support/hookkit.mk

# The payload is a plain library, not a DynamicLibraries tweak: it must load
# only through the stub's gated dlopen, never through the runtime's own
# injection. library.mk stages it to /usr/lib (no filter plist required) and
# the stub dlopens @THEOS_PACKAGE_INSTALL_PREFIX /usr/lib/ShadowCore.dylib.
LIBRARY_NAME = ShadowCore

ShadowCore_FILES = $(wildcard hooks/Universal/*.x) $(wildcard hooks/Adapters/*.x) hooks/Adapters/DeviceCheckHooks.m hooks/Universal/path_rewrite.c $(wildcard policy/*.m) shadowcore.x HookCoordinator.m SHDWHookSession.m HookAdapterBridge.m
ShadowCore_LIBRARIES = sandy
ShadowCore_FRAMEWORKS = Foundation IOKit
ShadowCore_EXTRA_FRAMEWORKS = Shadow HookKit
ShadowCore_PRIVATE_FRAMEWORKS = MobileCoreServices
# Generated single-source-of-truth header for the JB identifier arrays (see
# build-support/jb-identifiers.plist). Rendered into a gitignored build dir and
# added to the include path; AppEnvironment.x #includes it. Generation is wired
# below via before-all:: so it precedes every compile, including parallel ones.
SHADOW_GEN_DIR = .gen
SHADOW_JB_IDENTIFIERS_H = $(SHADOW_GEN_DIR)/jb-identifiers.h
ShadowCore_CFLAGS = -fobjc-arc -fvisibility=hidden -I. -I hooks -I$(SHADOW_GEN_DIR) -I../Shadow.framework/Headers $(SHADOW_HOOKKIT_CFLAGS)
ShadowCore_LOGOSFLAGS = -c generator=hookkit -c hook_inheritance=allow_inherited
ifneq ($(SHADOW_LANE),rootful-legacy)
ShadowCore_CFLAGS += -DSHADOW_CANONICAL_HOOKKIT=1
endif
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_CFLAGS += -DSHADOW_ROOTHIDE
endif
ShadowCore_LDFLAGS = -Wl,-x $(SHADOW_HOOKKIT_LDFLAGS) -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
# Xcode 16's new linker refuses a shared-cache-eligible dylib linking an
# ineligible one (ShadowCore -> @rpath/Shadow.framework/Shadow) on the
# rootful-modern lane; tweak dylibs are not shared-cache candidates anyway.
# Scoped: the legacy lane's old ld and the scheme lanes' drivers reject the
# bare flag, and rootless builds fine without it.
ifeq ($(THEOS_PACKAGE_SCHEME),)
ifneq ($(findstring 16.5,$(TARGET)),)
ShadowCore_LDFLAGS += -Wl,-not_for_dyld_shared_cache
endif
endif
ShadowCore_LDFLAGS += -F../
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_LDFLAGS += -lroothide
endif

include $(THEOS_MAKE_PATH)/library.mk

# Render the generated identifier header before any compilation. The generator
# is deterministic and leaves an unchanged output untouched (safe under -j and
# repeated builds); it exits non-zero on bad input, failing the build rather
# than compiling stale data.
SHADOW_JB_PLIST = ../../build-support/jb-identifiers.plist
SHADOW_GEN_JB = ../../scripts/gen-jb-identifiers.py

before-all::
	@mkdir -p $(SHADOW_GEN_DIR)
	python3 $(SHADOW_GEN_JB) $(SHADOW_JB_PLIST) $(SHADOW_JB_IDENTIFIERS_H)

internal-clean::
	rm -rf $(SHADOW_GEN_DIR)
