include $(THEOS)/makefiles/common.mk

TOOL_NAME = shdw

shdw_FILES = main.m
shdw_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers
shdw_LDFLAGS = -F../
shdw_CODESIGN_FLAGS = -Sentitlements.plist
shdw_INSTALL_PATH = /usr/local/bin
shdw_EXTRA_FRAMEWORKS = Shadow
shdw_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tool.mk
