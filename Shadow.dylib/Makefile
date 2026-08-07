INSTALL_TARGET_PROCESSES = SpringBoard
# LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

Shadow_FILES = $(wildcard hooks/*.x) dylib.x
Shadow_LIBRARIES = sandy
Shadow_FRAMEWORKS = Foundation
Shadow_EXTRA_FRAMEWORKS = Shadow HookKit RootBridge
Shadow_PRIVATE_FRAMEWORKS = MobileCoreServices
Shadow_CFLAGS = -fobjc-arc -fvisibility=hidden -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers -I../vendor/RootBridge.framework/Headers
Shadow_LDFLAGS = -Wl,-x -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
Shadow_LDFLAGS += -F../ -F../vendor

include $(THEOS_MAKE_PATH)/tweak.mk
