ARCHS ?= armv7 armv7s arm64 arm64e
TARGET ?= iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = HookKit.m vendor/fishhook/fishhook.c
HookKit_FRAMEWORKS = Foundation
HookKit_LIBRARIES = dobby
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_CFLAGS = -fobjc-arc -IHeaders
HookKit_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKit_LDFLAGS += -Lvendor/dobby

include $(THEOS_MAKE_PATH)/framework.mk
