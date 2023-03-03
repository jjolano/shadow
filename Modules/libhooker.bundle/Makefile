ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitLH
HookKitLH_BUNDLE_EXTENSION = bundle
HookKitLH_FILES = Module.m HKLH.m
HookKitLH_LIBRARIES = _libhooker _blackjack
HookKitLH_EXTRA_FRAMEWORKS = HookKit
HookKitLH_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitLH_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitLH_LDFLAGS += -Fvendor -Lvendor/libhooker
HookKitLH_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
