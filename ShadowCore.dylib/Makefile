INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

# Force LC_BUILD_VERSION (required for iOS 15+) instead of old LC_VERSION_MIN_IPHONEOS
VERSIONFLAGS = -Wl,-platform_version,ios,15.0,16.5

# The payload is a plain library, not a DynamicLibraries tweak: it must load
# only through the stub's gated dlopen, never through the runtime's own
# injection. library.mk stages it to /usr/lib (no filter plist required) and
# the stub dlopens @THEOS_PACKAGE_INSTALL_PREFIX /usr/lib/ShadowCore.dylib.
LIBRARY_NAME = ShadowCore

ShadowCore_FILES = $(wildcard hooks/*/*.x) hooks/Environment/DeviceCheckHooks.m hooks/FileHiding/path_rewrite.c $(wildcard policy/*.m) shadowcore.x HookCoordinator.m
ShadowCore_LIBRARIES = sandy
ShadowCore_FRAMEWORKS = Foundation IOKit
ShadowCore_EXTRA_FRAMEWORKS = Shadow HookKit
ShadowCore_PRIVATE_FRAMEWORKS = MobileCoreServices
ShadowCore_CFLAGS = -fobjc-arc -fvisibility=hidden -I. -I hooks -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_CFLAGS += -DSHADOW_ROOTHIDE
endif
ShadowCore_LDFLAGS = -Wl,-x -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib -Wl,-platform_version,ios,15.0,16.5
ShadowCore_LDFLAGS += -F../ -F../vendor
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_LDFLAGS += -lroothide
endif

include $(THEOS_MAKE_PATH)/library.mk
