INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

ShadowHooks = $(wildcard hooks/*.x)
ShadowAPI = $(wildcard ../api/*.m)

Shadow_FILES = $(ShadowHooks) $(ShadowAPI) dylib.x
Shadow_LIBRARIES = sandy
Shadow_FRAMEWORKS = Foundation CoreFoundation
Shadow_PRIVATE_FRAMEWORKS = AppSupport
Shadow_CFLAGS = -fobjc-arc -DTHEOS_LEAN_AND_MEAN

include $(THEOS_MAKE_PATH)/tweak.mk
