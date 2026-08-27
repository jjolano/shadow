TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
DTT_DIR ?= ../../.detector-deps/DTTJailbreakDetection/Sources/DTTJailbreakDetection

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = DTTJailbreakDetectionRunner
DTTJailbreakDetectionRunner_FILES = AppDelegate.m $(DTT_DIR)/DTTJailbreakDetection.m
DTTJailbreakDetectionRunner_CFLAGS = -I$(DTT_DIR)/include -fobjc-arc -fmodules-cache-path=/tmp/shadow-detector-dtt-module-cache
DTTJailbreakDetectionRunner_FRAMEWORKS = UIKit Foundation
DTTJailbreakDetectionRunner_INSTALL_PATH = /Applications
DTTJailbreakDetectionRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
