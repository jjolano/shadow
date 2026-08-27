TARGET ?= iphone:clang:16.5:13.0
ARCHS ?= arm64
FREERASP_ROOT ?= ../../.detector-deps/Free-RASP-iOS-6.4.0
TALSEC_FRAMEWORK := $(FREERASP_ROOT)/Talsec/TalsecRuntime.xcframework/ios-arm64/TalsecRuntime.framework

include $(THEOS)/makefiles/common.mk

# The Linux linker does not honor iOS 16's $ld$previous Swift-Foundation
# directives, so select the pre-iOS-16 stubs before Foundation is linked.
_THEOS_INTERNAL_LDFLAGS := -F$(THEOS)/sdks/iPhoneOS14.5.sdk/System/Library/Frameworks -L$(THEOS)/sdks/iPhoneOS14.5.sdk/usr/lib/swift $(_THEOS_INTERNAL_LDFLAGS)

APPLICATION_NAME = FreeRASPRunner
FreeRASPRunner_FILES = AppDelegate.swift
FreeRASPRunner_SWIFTFLAGS = -swift-version 5 -F$(dir $(TALSEC_FRAMEWORK)) -module-cache-path /tmp/shadow-detector-freerasp-module-cache
FreeRASPRunner_LDFLAGS = -F$(dir $(TALSEC_FRAMEWORK)) -framework TalsecRuntime -lswiftFoundation -rpath @executable_path/Frameworks
FreeRASPRunner_FRAMEWORKS = UIKit Foundation
FreeRASPRunner_INSTALL_PATH = /Applications
FreeRASPRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk

after-stage::
	$(ECHO_NOTHING)mkdir -p "$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app/Frameworks"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(TALSEC_FRAMEWORK)" "$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)$(TARGET_CODESIGN) -S "$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app/Frameworks/TalsecRuntime.framework/TalsecRuntime"$(ECHO_END)
