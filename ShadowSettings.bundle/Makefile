INSTALL_TARGET_PROCESSES = Preferences

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowSettings

ShadowSettings_FILES = $(wildcard *.m)
ShadowSettings_FRAMEWORKS = Foundation
ShadowSettings_EXTRA_FRAMEWORKS = Shadow AltList HookKit RootBridge
ShadowSettings_PRIVATE_FRAMEWORKS = Preferences
ShadowSettings_INSTALL_PATH = /Library/PreferenceBundles
ShadowSettings_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers -I../vendor/HookKit.framework/Headers -I../vendor/RootBridge.framework/Headers
ShadowSettings_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowSettings_LDFLAGS += -F../ -F../vendor

include $(THEOS_MAKE_PATH)/bundle.mk
