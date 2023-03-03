ARCHS ?= armv7 armv7s arm64 arm64e
TARGET ?= iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitFH
HookKitFH_BUNDLE_EXTENSION = bundle
HookKitFH_FILES = Module.m HKFH.m vendor/fishhook/fishhook.c
HookKitFH_EXTRA_FRAMEWORKS = HookKit
HookKitFH_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitFH_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitFH_LDFLAGS += -Fvendor
HookKitFH_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
