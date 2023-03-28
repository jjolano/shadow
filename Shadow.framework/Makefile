include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = Shadow

Shadow_FILES = Core.m Core+Utilities.m Backend.m Ruleset.m Settings.m
Shadow_FRAMEWORKS = Foundation CoreFoundation
Shadow_INSTALL_PATH = /Library/Frameworks
Shadow_CFLAGS = -fobjc-arc -IHeaders
Shadow_LDFLAGS = -install_name @rpath/Shadow.framework/Shadow

include $(THEOS_MAKE_PATH)/framework.mk
