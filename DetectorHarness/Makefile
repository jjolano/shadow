TARGET ?= iphone:clang:16.5:14.0
ARCHS ?= arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = ShadowDetectorHarness
ShadowDetectorHarness_FILES = main.m DetectorDashboard.m
ShadowDetectorHarness_CFLAGS = -fobjc-arc -fmodules-cache-path=/tmp/shadow-detector-dashboard-module-cache
ShadowDetectorHarness_FRAMEWORKS = UIKit Foundation
ShadowDetectorHarness_INSTALL_PATH = /Applications
ShadowDetectorHarness_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
