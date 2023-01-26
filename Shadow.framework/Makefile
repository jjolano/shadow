include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = Shadow

Shadow_FILES = $(wildcard ./*.m)
Shadow_FRAMEWORKS = Foundation
Shadow_INSTALL_PATH = /Library/Frameworks
Shadow_PRIVATE_FRAMEWORKS = AppSupport
Shadow_CFLAGS = -fobjc-arc -IHeaders/Shadow

include $(THEOS_MAKE_PATH)/framework.mk
