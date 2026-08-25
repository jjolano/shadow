INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

# The payload is a plain library, not a DynamicLibraries tweak: it must load
# only through the stub's gated dlopen, never through the runtime's own
# injection. library.mk stages it to /usr/lib (no filter plist required) and
# the stub dlopens @THEOS_PACKAGE_INSTALL_PREFIX /usr/lib/ShadowCore.dylib.
LIBRARY_NAME = ShadowCore

ShadowCore_FILES = $(wildcard hooks/*/*.x) hooks/Environment/DeviceCheckHooks.m hooks/FileHiding/path_rewrite.c $(wildcard policy/*.m) shadowcore.x HookCoordinator.m SHDWHookSession.m
ShadowCore_LIBRARIES = sandy
ShadowCore_FRAMEWORKS = Foundation IOKit
ShadowCore_EXTRA_FRAMEWORKS = Shadow HookKit
ShadowCore_PRIVATE_FRAMEWORKS = MobileCoreServices
ShadowCore_CFLAGS = -fobjc-arc -fvisibility=hidden -I. -I hooks -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers
ifneq ($(SHADOW_LANE),rootful-legacy)
ShadowCore_CFLAGS += -DSHADOW_CANONICAL_HOOKKIT=1
endif
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_CFLAGS += -DSHADOW_ROOTHIDE
endif
# Xcode 16's linker refuses a shared-cache-eligible dylib linking an
# ineligible one (ShadowCore -> @rpath/Shadow.framework/Shadow); tweak
# dylibs are not shared-cache candidates anyway.
ShadowCore_LDFLAGS = -Wl,-x -not_for_dyld_shared_cache -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowCore_LDFLAGS += -F../ -F../vendor
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_LDFLAGS += -lroothide
endif

include $(THEOS_MAKE_PATH)/library.mk
