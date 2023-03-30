ARCHS ?= armv7 armv7s arm64 arm64e
TARGET ?= iphone:clang:14.5:8.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitSubstrateModule
HookKitSubstrateModule_BUNDLE_EXTENSION = bundle
HookKitSubstrateModule_FILES = Module.m HKSubstrate.m
HookKitSubstrateModule_EXTRA_FRAMEWORKS = HookKit _CydiaSubstrate
HookKitSubstrateModule_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitSubstrateModule_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitSubstrateModule_LDFLAGS += -Fvendor
HookKitSubstrateModule_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
