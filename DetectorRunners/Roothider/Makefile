TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = RoothiderRunner
RoothiderRunner_FILES = AppDelegate.m
RoothiderRunner_CFLAGS = -fobjc-arc -fmodules-cache-path=/tmp/shadow-detector-roothider-module-cache
RoothiderRunner_FRAMEWORKS = UIKit Foundation
RoothiderRunner_INSTALL_PATH = /Applications
RoothiderRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
