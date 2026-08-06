include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = Shadow

Shadow_FILES = Core.m Core+Utilities.m Backend.m Ruleset.m Settings.m SystemRulesGenerator.m
Shadow_FRAMEWORKS = Foundation CoreFoundation
Shadow_EXTRA_FRAMEWORKS = RootBridge
Shadow_INSTALL_PATH = /Library/Frameworks
Shadow_CFLAGS = -fobjc-arc -fvisibility=hidden -IHeaders -I../vendor/RootBridge.framework/Headers
Shadow_LDFLAGS = -Wl,-x -F../vendor/ -install_name @rpath/Shadow.framework/Shadow
# -fvisibility=hidden hides everything; the export list below is the ONLY
# thing that stays linkable (theos never applies Shadow.tbd as an export
# list, so without this every ObjC class is stripped and the tweak can't
# link). Keep exported_symbols.txt in sync with the classes.
Shadow_LDFLAGS += -exported_symbols_list exported_symbols.txt
Shadow_LDFLAGS += -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib

include $(THEOS_MAKE_PATH)/framework.mk
