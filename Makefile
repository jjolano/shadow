ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:11.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

ShadowHooks = $(wildcard hooks/*.x)

Shadow_FILES = $(ShadowHooks) Tweak.x
Shadow_LIBRARIES = rocketbootstrap
Shadow_EXTRA_FRAMEWORKS = Cephei
Shadow_PRIVATE_FRAMEWORKS = AppSupport
Shadow_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += shadowd
SUBPROJECTS += shadowsettings
include $(THEOS_MAKE_PATH)/aggregate.mk
