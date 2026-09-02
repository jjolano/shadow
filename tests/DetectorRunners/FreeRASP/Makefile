TARGET ?= iphone:clang:16.5:13.0
ARCHS ?= arm64
FREERASP_ROOT ?= ../../../.detector-deps/Free-RASP-iOS-7.1.2
TALSEC_FRAMEWORK := $(FREERASP_ROOT)/Talsec/TalsecRuntime.xcframework/ios-arm64/TalsecRuntime.framework
FREERASP_COMPAT_FRAMEWORKS := /tmp/shadow-detector-freerasp-frameworks

include $(THEOS)/makefiles/common.mk

# Linux's linker does not honor iOS 16's $ld$previous Swift-Foundation
# directives, so provide the SDK Foundation stubs before linking.
_THEOS_INTERNAL_LDFLAGS := -F$(FREERASP_COMPAT_FRAMEWORKS) -L$(THEOS)/sdks/iPhoneOS14.5.sdk/usr/lib/swift $(_THEOS_INTERNAL_LDFLAGS)

before-all::
	$(ECHO_NOTHING)mkdir -p "$(FREERASP_COMPAT_FRAMEWORKS)"$(ECHO_END)
	$(ECHO_NOTHING)ln -sfn "$(THEOS)/sdks/iPhoneOS14.5.sdk/System/Library/Frameworks/Foundation.framework" "$(FREERASP_COMPAT_FRAMEWORKS)/Foundation.framework"$(ECHO_END)

APPLICATION_NAME = FreeRASPRunner
FreeRASPRunner_FILES = AppDelegate.swift Probe.m ../RunnerSupport.swift ../RunnerSupport.m
FreeRASPRunner_SWIFT_BRIDGING_HEADER = ../RunnerSupportC.h
FreeRASPRunner_SWIFTFLAGS = -swift-version 5 -F$(dir $(TALSEC_FRAMEWORK)) -module-cache-path /tmp/shadow-detector-freerasp-module-cache -Xcc -Wno-error=unknown-warning-option -Xcc -Wno-error=incomplete-umbrella
FreeRASPRunner_LDFLAGS = -F$(dir $(TALSEC_FRAMEWORK)) -framework TalsecRuntime -lswiftFoundation -rpath @executable_path/Frameworks
FreeRASPRunner_FRAMEWORKS = UIKit Foundation
FreeRASPRunner_INSTALL_PATH = /Applications
FreeRASPRunner_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk

after-stage::
	$(ECHO_NOTHING)mkdir -p "$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app/Frameworks"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(TALSEC_FRAMEWORK)" "$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)$(TARGET_CODESIGN) -S "$(THEOS_STAGING_DIR)/Applications/FreeRASPRunner.app/Frameworks/TalsecRuntime.framework/TalsecRuntime"$(ECHO_END)
