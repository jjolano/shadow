INSTALL_TARGET_PROCESSES = Preferences

include ../../build-support/build-lanes.mk
include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowSettings

ShadowSettings_FILES = $(wildcard *.m)
ShadowSettings_FRAMEWORKS = Foundation
ShadowSettings_EXTRA_FRAMEWORKS = Shadow AltList MobileCoreServices
ShadowSettings_PRIVATE_FRAMEWORKS = Preferences
ShadowSettings_INSTALL_PATH = /Library/PreferenceBundles
ShadowSettings_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers
ifeq ($(SHADOW_LANE),rootful-legacy)
ShadowSettings_CFLAGS += -Wno-unguarded-availability-new
endif
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowSettings_CFLAGS += -DSHADOW_ROOTHIDE
endif
ShadowSettings_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowSettings_LDFLAGS += -F../ -F../../vendor
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowSettings_LDFLAGS += -lroothide
# bundle.mk stamps an absolute LC_ID_DYLIB ($(THEOS_PACKAGE_INSTALL_PREFIX)
# is empty under roothide); roothide requires loader-relative ids and
# check-binary-compat enforces @loader_path/.jbroot/. Instance LDFLAGS come
# after internal ones, so this override wins.
ShadowSettings_LDFLAGS += -Wl,-install_name,@loader_path/.jbroot$(ShadowSettings_INSTALL_PATH)/ShadowSettings
endif

include $(THEOS_MAKE_PATH)/bundle.mk
