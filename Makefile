ARCHS := armv7 armv7s arm64 arm64e
TARGET := iphone:clang:12.2:8.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = 0Shadow
$(TWEAK_NAME)_FILES = Classes/Shadow.m Tweak.xm
$(TWEAK_NAME)_EXTRA_FRAMEWORKS = Cephei
$(TWEAK_NAME)_CFLAGS = -fobjc-arc -DShadow="_$(shell git describe --always)"

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
SUBPROJECTS += ShadowPreferences
include $(THEOS_MAKE_PATH)/aggregate.mk
