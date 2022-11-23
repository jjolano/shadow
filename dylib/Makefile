INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

ShadowHooks = $(wildcard hooks/*.x)
ShadowAPI = $(wildcard ../api/*.m)

Shadow_FILES = $(ShadowHooks) $(ShadowAPI) dylib.x
Shadow_LIBRARIES = rocketbootstrap
Shadow_FRAMEWORKS = Foundation UIKit CoreFoundation
Shadow_EXTRA_FRAMEWORKS = 
Shadow_PRIVATE_FRAMEWORKS = AppSupport
Shadow_CFLAGS = -fobjc-arc -DROCKETBOOTSTRAP_LOAD_DYNAMIC -DTHEOS_LEAN_AND_MEAN

include $(THEOS_MAKE_PATH)/tweak.mk
