ARCHS := armv7 armv7s arm64 arm64e
TARGET := iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = HookKit.m $(wildcard vendor/fishhook/fishhook.c)
HookKit_PUBLIC_HEADERS = HookKit.h
HookKit_FRAMEWORKS = Foundation
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_CFLAGS = -fobjc-arc -DTHEOS_LEAN_AND_MEAN

include $(THEOS_MAKE_PATH)/framework.mk
