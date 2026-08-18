INSTALL_TARGET_PROCESSES = SpringBoard
# LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

Shadow_FILES = dylib.x
Shadow_LIBRARIES = sandy
Shadow_FRAMEWORKS = Foundation
Shadow_CFLAGS = -fobjc-arc -fvisibility=hidden -I../Shadow.framework/Headers -I../ShadowCore.dylib -I../vendor/HookKit.framework/Headers
Shadow_LDFLAGS = -Wl,-x

include $(THEOS_MAKE_PATH)/tweak.mk
