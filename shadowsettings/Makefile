ARCHS = arm64 arm64e
include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowSettings

ShadowSettings_FILES = SHDWRootListController.m
ShadowSettings_INSTALL_PATH = /Library/PreferenceBundles
ShadowSettings_LIBRARIES = sparkapplist
ShadowSettings_FRAMEWORKS = UIKit
ShadowSettings_EXTRA_FRAMEWORKS = Cephei CepheiPrefs
ShadowSettings_PRIVATE_FRAMEWORKS = Preferences
ShadowSettings_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk

internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences$(ECHO_END)
	$(ECHO_NOTHING)cp entry.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/ShadowSettings.plist$(ECHO_END)
