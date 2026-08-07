INSTALL_TARGET_PROCESSES = SpringBoard
# LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ShadowCore

ShadowCore_FILES = $(wildcard hooks/*.x) dylib.x
ShadowCore_LIBRARIES = sandy
ShadowCore_FRAMEWORKS = Foundation
ShadowCore_EXTRA_FRAMEWORKS = Shadow HookKit RootBridge
ShadowCore_PRIVATE_FRAMEWORKS = MobileCoreServices
ShadowCore_CFLAGS = -fobjc-arc -fvisibility=hidden -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers -I../vendor/RootBridge.framework/Headers
ShadowCore_LDFLAGS = -Wl,-x -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowCore_LDFLAGS += -F../ -F../vendor

include $(THEOS_MAKE_PATH)/tweak.mk
