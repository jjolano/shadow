ARCHS ?= arm64 arm64e
# TARGET: clang:latest keeps the toolchain current; the 12.0 floor matches
# control's Depends: firmware (>= 12.0). Note: theos bumps the arm64e slice
# minos to 14.0 on this floor.
TARGET ?= iphone:clang:latest:12.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = HKSubstitutor.m vendor/fishhook/fishhook.c
HookKit_FRAMEWORKS = Foundation
HookKit_EXTRA_FRAMEWORKS = RootBridge
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_PUBLIC_HEADERS = Headers/HookKit.h Headers/HookKit
HookKit_CFLAGS = -fobjc-arc -IHeaders -Ivendor -Ivendor/RootBridge.framework/Headers
HookKit_LDFLAGS = -Fvendor -install_name @rpath/HookKit.framework/HookKit
HookKit_LDFLAGS += -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib

include $(THEOS_MAKE_PATH)/framework.mk
