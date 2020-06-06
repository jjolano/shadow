INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Shadow

Shadow_FILES = Tweak.x
Shadow_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
