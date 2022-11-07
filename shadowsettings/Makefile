ARCHS = armv7 arm64 arm64e
TARGET = iphone:clang:13.0:7.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowSettings

ShadowSettings_FILES = SHDWRootListController.m
ShadowSettings_FRAMEWORKS = UIKit
ShadowSettings_EXTRA_FRAMEWORKS = Cephei CepheiPrefs AltList
ShadowSettings_PRIVATE_FRAMEWORKS = Preferences
ShadowSettings_INSTALL_PATH = /Library/PreferenceBundles
ShadowSettings_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk
