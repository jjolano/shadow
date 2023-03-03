ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitDobby
HookKitDobby_BUNDLE_EXTENSION = bundle
HookKitDobby_FILES = Module.m HKDobby.m
HookKitDobby_LIBRARIES = dobby
HookKitDobby_EXTRA_FRAMEWORKS = HookKit
HookKitDobby_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitDobby_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitDobby_LDFLAGS += -Fvendor -Lvendor/dobby
HookKitDobby_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
