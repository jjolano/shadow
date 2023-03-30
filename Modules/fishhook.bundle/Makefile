ARCHS ?= armv7 armv7s arm64 arm64e
TARGET ?= iphone:clang:14.5:8.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitFishhookModule
HookKitFishhookModule_BUNDLE_EXTENSION = bundle
HookKitFishhookModule_FILES = Module.m HKFH.m vendor/fishhook/fishhook.c
HookKitFishhookModule_EXTRA_FRAMEWORKS = HookKit
HookKitFishhookModule_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitFishhookModule_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitFishhookModule_LDFLAGS += -Fvendor
HookKitFishhookModule_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
