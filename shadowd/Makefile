ARCHS = armv7 arm64 arm64e
TARGET = iphone:clang:latest:7.0
include $(THEOS)/makefiles/common.mk

TOOL_NAME = shadowd

shadowd_FILES = ../api/Shadow.m ShadowXPC.m main.m
shadowd_LIBRARIES = rocketbootstrap
shadowd_PRIVATE_FRAMEWORKS = AppSupport
shadowd_INSTALL_PATH = /usr/libexec
shadowd_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tool.mk

after-shadowd-stage::
	$(ECHO_NOTHING)$(FAKEROOT) chown root:wheel $(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadowd.plist$(ECHO_END)
