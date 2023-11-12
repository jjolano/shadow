include $(THEOS)/makefiles/common.mk

TOOL_NAME = shdw

shdw_FILES = main.m
shdw_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers -I../vendor/RootBridge.framework/Headers
shdw_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath @loader_path/.jbroot/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib -rpath @loader_path/.jbroot/usr/lib
shdw_LDFLAGS += -F../ -F../vendor/
shdw_CODESIGN_FLAGS = -Sentitlements.plist
shdw_INSTALL_PATH = /usr/local/bin
shdw_EXTRA_FRAMEWORKS = Shadow RootBridge
shdw_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tool.mk
