ARCHS ?= armv7 armv7s arm64 arm64e
TARGET ?= iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitSubstitute
HookKitSubstitute_BUNDLE_EXTENSION = bundle
HookKitSubstitute_FILES = Module.m HKSubstitute.m
HookKitSubstitute_LIBRARIES = _substitute
HookKitSubstitute_EXTRA_FRAMEWORKS = HookKit
HookKitSubstitute_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitSubstitute_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitSubstitute_LDFLAGS += -Fvendor -Lvendor/substitute
HookKitSubstitute_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
