include ../build-lanes.mk
include $(THEOS)/makefiles/common.mk

TOOL_NAME = shdw

shdw_FILES = main.m
shdw_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
shdw_CFLAGS += -DSHADOW_ROOTHIDE
endif
shdw_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
shdw_LDFLAGS += -F../ -F../vendor/
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
shdw_LDFLAGS += -lroothide
endif
shdw_CODESIGN_FLAGS = -Sentitlements.plist
shdw_INSTALL_PATH = /usr/local/bin
shdw_EXTRA_FRAMEWORKS = Shadow
shdw_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tool.mk
