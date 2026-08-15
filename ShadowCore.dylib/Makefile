INSTALL_TARGET_PROCESSES = SpringBoard
# LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ShadowCore

ShadowCore_FILES = $(wildcard hooks/*/*.x) hooks/Environment/DeviceCheckHooks.m $(wildcard policy/*.m) dylib.x HookCoordinator.m
ShadowCore_LIBRARIES = sandy
ShadowCore_FRAMEWORKS = Foundation IOKit
ShadowCore_EXTRA_FRAMEWORKS = Shadow HookKit
ShadowCore_PRIVATE_FRAMEWORKS = MobileCoreServices
ShadowCore_CFLAGS = -fobjc-arc -fvisibility=hidden -I. -I hooks -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_CFLAGS += -DSHADOW_ROOTHIDE
endif
ShadowCore_LDFLAGS = -Wl,-x -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowCore_LDFLAGS += -F../ -F../vendor
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowCore_LDFLAGS += -lroothide
endif

include $(THEOS_MAKE_PATH)/tweak.mk
