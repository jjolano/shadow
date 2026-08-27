TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
IOS_SECURITY_SUITE_DIR ?= ../../.detector-deps/IOSSecuritySuite/IOSSecuritySuite

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = IOSSecuritySuiteRunner
IOSSecuritySuiteRunner_FILES = AppDelegate.swift $(wildcard $(IOS_SECURITY_SUITE_DIR)/*.swift)
IOSSecuritySuiteRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-iossecuritysuite-module-cache
IOSSecuritySuiteRunner_FRAMEWORKS = UIKit Foundation
IOSSecuritySuiteRunner_LDFLAGS = -lswiftFoundation
IOSSecuritySuiteRunner_INSTALL_PATH = /Applications
IOSSecuritySuiteRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk
