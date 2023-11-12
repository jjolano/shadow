# INSTALL_TARGET_PROCESSES = SpringBoard
INSTALL_TARGET_PROCESSES = 
# LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

Shadow_FILES = $(wildcard hooks/*.x) dylib.x
Shadow_LIBRARIES = sandy
Shadow_FRAMEWORKS = Foundation
Shadow_EXTRA_FRAMEWORKS = Shadow HookKit RootBridge
Shadow_PRIVATE_FRAMEWORKS = MobileCoreServices
Shadow_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers -I../vendor/RootBridge.framework/Headers
Shadow_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath @loader_path/.jbroot/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib -rpath @loader_path/.jbroot/usr/lib
Shadow_LDFLAGS += -F../ -F../vendor
Shadow_LDFLAGS += -weak_framework CydiaSubstrate

include $(THEOS_MAKE_PATH)/tweak.mk
