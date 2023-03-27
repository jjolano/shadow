ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:14.5:14.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitDobbyModule
HookKitDobbyModule_BUNDLE_EXTENSION = bundle
HookKitDobbyModule_FILES = Module.m HKDobby.m
HookKitDobbyModule_LIBRARIES = dobby
HookKitDobbyModule_EXTRA_FRAMEWORKS = HookKit
HookKitDobbyModule_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitDobbyModule_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitDobbyModule_LDFLAGS += -Fvendor -Lvendor/dobby
HookKitDobbyModule_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
