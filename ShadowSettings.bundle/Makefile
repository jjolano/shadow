INSTALL_TARGET_PROCESSES = Preferences

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowSettings

ShadowSettings_FILES = $(wildcard *.m)
ShadowSettings_FRAMEWORKS = Foundation
ShadowSettings_EXTRA_FRAMEWORKS = Shadow AltList HookKit
ifneq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowSettings_EXTRA_FRAMEWORKS += RootBridge
endif
ShadowSettings_PRIVATE_FRAMEWORKS = Preferences
ShadowSettings_INSTALL_PATH = /Library/PreferenceBundles
ShadowSettings_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers
ifneq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowSettings_CFLAGS += -I../vendor/RootBridge.framework/Headers
else
ShadowSettings_CFLAGS += -DSHADOW_ROOTHIDE
endif
ShadowSettings_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowSettings_LDFLAGS += -F../ -F../vendor
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowSettings_LDFLAGS += -lroothide
endif

include $(THEOS_MAKE_PATH)/bundle.mk
