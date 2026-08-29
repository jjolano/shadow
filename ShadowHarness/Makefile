TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
DEPS ?= ../.detector-deps
FW_BUILD := detector-frameworks
SHDW_FW_OBJ_DIR := $(shell test -d "$(FW_BUILD)/.theos/obj/debug" && echo "$(FW_BUILD)/.theos/obj/debug" || echo "$(FW_BUILD)/.theos/obj")
TALSEC_ROOT := $(DEPS)/Free-RASP-iOS-7.1.2/Talsec/TalsecRuntime.xcframework/ios-arm64
TALSEC_DIR := $(TALSEC_ROOT)/TalsecRuntime.framework

include $(THEOS)/makefiles/common.mk
APPLICATION_NAME = ShadowHarness
SN_DIR = $(DEPS)/SafetyNet
SN_FILES := $(shell find $(SN_DIR)/Sources/SafetyNet -name '*.swift' | sort)
ShadowHarness_FILES = main.m AppDelegate.m SceneDelegate.m DetectorDashboard.m StatusViewController.m Battery.m Detectors.m TalsecBridge.swift $(SN_FILES) detector-frameworks/bridges/SafetyNetBridge.swift $(DEPS)/SafetyNet/Sources/SafetyNetObjC/AntiDebugBridge.m ../tests/detectors/ShadowDetector.m $(DEPS)/DTTJailbreakDetection/Sources/DTTJailbreakDetection/DTTJailbreakDetection.m $(DEPS)/JailMonkey/JailMonkey/JailMonkey.m $(DEPS)/JailbreakDetector/main.m
ShadowHarness_CFLAGS = -fobjc-arc -DSHADOW_HARNESS -Wno-error=deprecated-declarations -I../tests/detectors -I../Shadow.framework/Headers -I$(DEPS)/DTTJailbreakDetection/Sources/DTTJailbreakDetection/include -I$(DEPS)/JailMonkey/JailMonkey -I$(DEPS)/JailbreakDetector -I$(SN_DIR)/Sources/SafetyNetObjC/include -Istubs
ShadowHarness_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-harness-swift-module-cache -I$(SN_DIR)/Sources/SafetyNetObjC -Iconcurrency -F$(TALSEC_ROOT) -Xcc -Wno-error=unknown-warning-option -Xcc -Wno-error=incomplete-umbrella
ShadowHarness_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib -rpath @executable_path/Frameworks
ShadowHarness_LDFLAGS += -F../ -F../vendor/ -F$(TALSEC_ROOT) -lswiftFoundation -framework TalsecRuntime -L$(THEOS)/sdks/iPhoneOS16.5.sdk/usr/lib/swift -lswift_Concurrency
ShadowHarness_EXTRA_FRAMEWORKS = Shadow
ShadowHarness_FRAMEWORKS = UIKit Foundation CryptoKit
ShadowHarness_INSTALL_PATH = /Applications
ShadowHarness_RESOURCE_DIRS = Resources
include $(THEOS_MAKE_PATH)/application.mk
after-stage::
	$(ECHO_NOTHING)test -d "$(SHDW_FW_OBJ_DIR)" || { echo "detector frameworks not built; run scripts/build-detector-harness.sh first" >&2; exit 1; }$(ECHO_END)
	$(ECHO_NOTHING)rm -rf "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks"$(ECHO_END)
	$(ECHO_NOTHING)mkdir -p "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(SHDW_FW_OBJ_DIR)/IOSSecuritySuite.framework" "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(SHDW_FW_OBJ_DIR)/JailbreakDetector.framework" "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(SHDW_FW_OBJ_DIR)/SecurityToolkit.framework" "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(SHDW_FW_OBJ_DIR)/BATJailbreakGuard.framework" "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(SHDW_FW_OBJ_DIR)/DeviceSecurityKit.framework" "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)cp -R "$(TALSEC_DIR)" "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"$(ECHO_END)
	$(ECHO_NOTHING)for fw in IOSSecuritySuite JailbreakDetector SecurityToolkit BATJailbreakGuard DeviceSecurityKit TalsecRuntime; do $(TARGET_CODESIGN) -S "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/$$fw.framework/$$fw" || exit 1; done$(ECHO_END)
