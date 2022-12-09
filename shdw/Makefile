include $(THEOS)/makefiles/common.mk

TOOL_NAME = shdw

ShadowAPI = $(wildcard ../api/*.m)

shdw_FILES = $(ShadowAPI) main.m
shdw_CFLAGS = -fobjc-arc -DTHEOS_LEAN_AND_MEAN
shdw_CODESIGN_FLAGS = -Sentitlements.plist
shdw_INSTALL_PATH = /usr/local/bin
shdw_PRIVATE_FRAMEWORKS = AppSupport
shdw_FRAMEWORKS = Foundation CoreFoundation

include $(THEOS_MAKE_PATH)/tool.mk
