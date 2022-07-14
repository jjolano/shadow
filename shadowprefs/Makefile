ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:11.0
include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowPrefs

# ShadowPrefs_FILES = SHDWRootListController.m
ShadowPrefs_FILES = $(wildcard *.m)
ShadowPrefs_INSTALL_PATH = /Library/PreferenceBundles
ShadowPrefs_LIBRARIES = applist
ShadowPrefs_FRAMEWORKS = UIKit
ShadowPrefs_EXTRA_FRAMEWORKS = Cephei CepheiPrefs
ShadowPrefs_PRIVATE_FRAMEWORKS = Preferences
ShadowPrefs_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk

internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences$(ECHO_END)
	$(ECHO_NOTHING)cp entry.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/ShadowPrefs.plist$(ECHO_END)
