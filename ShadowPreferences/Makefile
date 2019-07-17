ARCHS := armv7 armv7s arm64 arm64e
TARGET := iphone:clang:12.2:8.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowPreferences
$(BUNDLE_NAME)_FILES = SHDWRootListController.m ../Classes/Shadow.m
$(BUNDLE_NAME)_INSTALL_PATH = /Library/PreferenceBundles
$(BUNDLE_NAME)_FRAMEWORKS = UIKit
$(BUNDLE_NAME)_EXTRA_FRAMEWORKS = Cephei CepheiPrefs
$(BUNDLE_NAME)_PRIVATE_FRAMEWORKS = Preferences
$(BUNDLE_NAME)_LIBRARIES = applist

include $(THEOS_MAKE_PATH)/bundle.mk

internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences$(ECHO_END)
	$(ECHO_NOTHING)cp entry.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/ShadowPreferences.plist$(ECHO_END)
