INSTALL_TARGET_PROCESSES = SpringBoard
# LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

ShadowHooks = $(wildcard hooks/*.x)
ShadowAPI = $(wildcard ../api/*.m)

Shadow_FILES = $(ShadowHooks) $(ShadowAPI) dylib.x
Shadow_LIBRARIES = sandy
Shadow_FRAMEWORKS = Foundation
Shadow_EXTRA_FRAMEWORKS = HookKit
Shadow_PRIVATE_FRAMEWORKS = AppSupport MobileCoreServices
Shadow_CFLAGS = -fobjc-arc -DTHEOS_LEAN_AND_MEAN
Shadow_LDFLAGS = -weak_framework CydiaSubstrate

include $(THEOS_MAKE_PATH)/tweak.mk
