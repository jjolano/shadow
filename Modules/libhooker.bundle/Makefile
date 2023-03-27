ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:14.5:11.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitLHModule
HookKitLHModule_BUNDLE_EXTENSION = bundle
HookKitLHModule_FILES = Module.m HKLH.m
HookKitLHModule_LIBRARIES = _libhooker _blackjack
HookKitLHModule_EXTRA_FRAMEWORKS = HookKit
HookKitLHModule_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitLHModule_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitLHModule_LDFLAGS += -Fvendor -Lvendor/libhooker
HookKitLHModule_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
