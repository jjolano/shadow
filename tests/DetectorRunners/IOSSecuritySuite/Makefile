TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = IOSSecuritySuiteRunner
IOSSecuritySuiteRunner_FILES = AppDelegate.swift ../RunnerSupport.swift ../RunnerSupport.m
IOSSecuritySuiteRunner_SWIFT_BRIDGING_HEADER = ../RunnerSupportC.h
IOSSecuritySuiteRunner_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-detector-iossecuritysuite-module-cache
IOSSecuritySuiteRunner_FRAMEWORKS = UIKit Foundation
IOSSecuritySuiteRunner_EXTRA_FRAMEWORKS = Shadow
IOSSecuritySuiteRunner_LDFLAGS = -F../../ -lswiftFoundation -rpath @executable_path/Frameworks -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks
IOSSecuritySuiteRunner_INSTALL_PATH = /Applications
IOSSecuritySuiteRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk

after-stage::
	$(ECHO_NOTHING)test -f "../../ShadowHarness/detector-frameworks/.theos/_/Library/Frameworks/IOSSecuritySuite.framework/IOSSecuritySuite" || { echo "build ShadowHarness/detector-frameworks first" >&2; exit 1; }; \
	rm -rf "$(THEOS_STAGING_DIR)/Applications/IOSSecuritySuiteRunner.app/Frameworks/IOSSecuritySuite.framework"; \
	mkdir -p "$(THEOS_STAGING_DIR)/Applications/IOSSecuritySuiteRunner.app/Frameworks"; \
	cp -R "../../ShadowHarness/detector-frameworks/.theos/_/Library/Frameworks/IOSSecuritySuite.framework" "$(THEOS_STAGING_DIR)/Applications/IOSSecuritySuiteRunner.app/Frameworks/"$(ECHO_END)
