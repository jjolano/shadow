ARCHS := armv7 armv7s arm64 arm64e
TARGET := iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = HookKit.m $(wildcard vendor/fishhook/fishhook.c)
HookKit_PUBLIC_HEADERS = HookKit.h
HookKit_FRAMEWORKS = Foundation
HookKit_EXTRA_FRAMEWORKS = CydiaSubstrate
HookKit_LIBRARIES = dobby
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_CFLAGS = -fobjc-arc
HookKit_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKit_LDFLAGS += -Lvendor/dobby -weak_framework CydiaSubstrate

include $(THEOS_MAKE_PATH)/framework.mk
