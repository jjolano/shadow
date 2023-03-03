ARCHS ?= armv7 armv7s arm64 arm64e
TARGET ?= iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitSubstrate
HookKitSubstrate_BUNDLE_EXTENSION = bundle
HookKitSubstrate_FILES = Module.m HKSubstrate.m
HookKitSubstrate_LIBRARIES = _substrate
HookKitSubstrate_EXTRA_FRAMEWORKS = HookKit
HookKitSubstrate_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitSubstrate_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitSubstrate_LDFLAGS += -Fvendor -Lvendor/substrate
HookKitSubstrate_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
