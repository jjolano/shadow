ARCHS = armv7 arm64 arm64e
TARGET = iphone:clang:latest:7.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

ShadowHooks = $(wildcard hooks/*.x)

Shadow_FILES = $(ShadowHooks) Tweak.x
# Shadow_LIBRARIES = rocketbootstrap
# Shadow_EXTRA_FRAMEWORKS = Cephei
Shadow_PRIVATE_FRAMEWORKS = AppSupport
Shadow_CFLAGS = -fobjc-arc -DROCKETBOOTSTRAP_LOAD_DYNAMIC

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += shadowd
include $(THEOS_MAKE_PATH)/aggregate.mk
