include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = Shadow

Shadow_FILES = Core.m Core+Utilities.m Backend.m Ruleset.m Settings.m
Shadow_FRAMEWORKS = Foundation CoreFoundation
Shadow_EXTRA_FRAMEWORKS = RootBridge
Shadow_INSTALL_PATH = /Library/Frameworks
Shadow_CFLAGS = -fobjc-arc -IHeaders -I../vendor/RootBridge.framework/Headers
Shadow_LDFLAGS = -F../vendor/ -install_name @rpath/Shadow.framework/Shadow
Shadow_LDFLAGS += -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath @loader_path/.jbroot/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib -rpath @loader_path/.jbroot/usr/lib

include $(THEOS_MAKE_PATH)/framework.mk
