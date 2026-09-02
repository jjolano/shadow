TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
ROOTHIDER_DIR ?= ../../../.detector-deps/JailbreakDetector

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = RoothiderRunner
RoothiderRunner_FILES = AppDelegate.m ../RunnerSupport.m $(ROOTHIDER_DIR)/main.m
RoothiderRunner_CFLAGS = -fobjc-arc -I../../ShadowHarness/stubs -I$(ROOTHIDER_DIR) -fmodules-cache-path=/tmp/shadow-detector-roothider-module-cache
RoothiderRunner_FRAMEWORKS = UIKit Foundation Security LocalAuthentication
RoothiderRunner_INSTALL_PATH = /Applications
RoothiderRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
