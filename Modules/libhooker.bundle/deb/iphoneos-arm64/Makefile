ARCHS := arm64 arm64e
TARGET := iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += ../../
include $(THEOS_MAKE_PATH)/aggregate.mk

internal-stage::
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/var/jb$(ECHO_END)
	$(ECHO_NOTHING)mv $(THEOS_STAGING_DIR)/Library $(THEOS_STAGING_DIR)/var/jb/Library$(ECHO_END)
