TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
ISJB_DIR ?= ../../../.detector-deps/isJailbroken/isJailbroken

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = isJailbrokenRunner
isJailbrokenRunner_FILES = AppDelegate.m ../RunnerSupport.m $(ISJB_DIR)/JB.m
isJailbrokenRunner_CFLAGS = -I$(ISJB_DIR) -fobjc-arc -fblocks -I$(THEOS_PROJECT_DIR) -fmodules-cache-path=/tmp/shadow-detector-isjailbroken-module-cache
isJailbrokenRunner_FRAMEWORKS = UIKit Foundation
isJailbrokenRunner_INSTALL_PATH = /Applications
isJailbrokenRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
