TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
JAILMONKEY_DIR ?= ../../../.detector-deps/JailMonkey/JailMonkey

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = JailMonkeyRunner
JailMonkeyRunner_FILES = AppDelegate.m ../RunnerSupport.m $(JAILMONKEY_DIR)/JailMonkey.m
JailMonkeyRunner_CFLAGS = -fobjc-arc -fblocks -I$(THEOS_PROJECT_DIR) -fmodules-cache-path=/tmp/shadow-detector-jailmonkey-module-cache
JailMonkeyRunner_FRAMEWORKS = UIKit Foundation
JailMonkeyRunner_INSTALL_PATH = /Applications
JailMonkeyRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
