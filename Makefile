ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:16.5:12.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = HKSubstitutor.m vendor/fishhook/fishhook.c
HookKit_FRAMEWORKS = Foundation
HookKit_EXTRA_FRAMEWORKS = RootBridge
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_CFLAGS = -fobjc-arc -IHeaders -Ivendor -Ivendor/RootBridge.framework/Headers
HookKit_LDFLAGS = -Fvendor -install_name @rpath/HookKit.framework/HookKit
HookKit_LDFLAGS += -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib

include $(THEOS_MAKE_PATH)/framework.mk
