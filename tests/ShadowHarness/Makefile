# The Harness runs every detector IN-PROCESS: the same upstream sources the
# old isolated runner apps compiled are built directly into ShadowHarness
# and executed sequentially by Detectors.m — no app flips, no URL schemes,
# no TCP. Each detector runs synchronously on a worker queue and writes its
# report straight to /var/mobile/Documents/ShadowDetectorTests/<id>.json.
#
# Deliberate exclusions from the in-process build (documented per row):
# - SafetyNet AntiDebugBridge.m: its PT_DENY_ATTACH constructor would fire
#   on the harness itself. DebuggerDetector rows that need it report
#   notChecked with an explicit message.
# - Forking probes (JailMonkey canFork, isJailbroken fork): replaced by a
#   posix_spawn dry-run in SHDWEmbedded.m (same signal, no child survives).
TARGET ?= iphone:clang:14.5:14.0
ARCHS ?= arm64
SHDW_DYLDPROBE_OBJ_DIR := ../tools/dyldprobe/.theos/obj

# Upstream detector sources (same inputs the old runner apps compiled).
DTT_DIR ?= ../../.detector-deps/DTTJailbreakDetection/Sources/DTTJailbreakDetection
JAILMONKEY_DIR ?= ../../.detector-deps/JailMonkey/JailMonkey
ISJB_DIR ?= ../../.detector-deps/isJailbroken/isJailbroken
ROOTHIDER_DIR ?= ../../.detector-deps/JailbreakDetector
SWIFTYJBD_DIR ?= ../../.detector-deps/SwiftyJBD
SAFETYNET_DIR ?= ../../.detector-deps/SafetyNet/Sources/SafetyNet
SAFETYNET_OBJC_DIR ?= ../../.detector-deps/SafetyNet/Sources/SafetyNetObjC
# TalsecRuntime ships here via build-detector-harness.sh (patched copy).
TALSEC_FW_DIR ?= /tmp/shadow-harness-talsec
FW_LIB_DIR := detector-frameworks/.theos/_/Library/Frameworks

include $(THEOS)/makefiles/common.mk

# Linux's linker does not honor iOS 16's $ld$previous Swift-Foundation
# directives, so provide the SDK Foundation stubs before linking (same as
# the old FreeRASP runner did).
_THEOS_INTERNAL_LDFLAGS := -F/tmp/shadow-harness-compat-frameworks -L$(THEOS)/sdks/iPhoneOS14.5.sdk/usr/lib/swift $(_THEOS_INTERNAL_LDFLAGS)

APPLICATION_NAME = ShadowHarness
ShadowHarness_FILES = main.m AppDelegate.m SceneDelegate.m DetectorDashboard.m StatusViewController.m Battery.m Detectors.m SHDWEmbedded.m EmbeddedDrivers.swift TalsecBridge.swift ../tools/dyldprobe/main.m ../detectors/ShadowDetector.m
# ObjC upstream one-shot sources.
ShadowHarness_FILES += $(DTT_DIR)/DTTJailbreakDetection.m
ShadowHarness_FILES += $(JAILMONKEY_DIR)/JailMonkey.m
ShadowHarness_FILES += $(ISJB_DIR)/JB.m
ShadowHarness_FILES += $(ROOTHIDER_DIR)/main.m
ShadowHarness_FILES += $(SAFETYNET_OBJC_DIR)/AntiDebugBridge.m
ShadowHarness_FILES += ../DetectorRunners/FreeRASP/Probe.m
# Swift upstream one-shot sources (SafetyNet minus the async facade; the
# embedded driver calls the synchronous detectors directly).
ShadowHarness_FILES += $(SAFETYNET_DIR)/Detectors/DebuggerDetector.swift
ShadowHarness_FILES += $(SAFETYNET_DIR)/Detectors/FileIntegrityChecker.swift
ShadowHarness_FILES += $(SAFETYNET_DIR)/Detectors/HookDetector.swift
ShadowHarness_FILES += $(SAFETYNET_DIR)/Detectors/IntegrityValidator.swift
ShadowHarness_FILES += $(SAFETYNET_DIR)/Detectors/JailbreakDetector.swift
ShadowHarness_FILES += $(SAFETYNET_DIR)/Detectors/ProxyDetector.swift
ShadowHarness_FILES += $(SAFETYNET_DIR)/Internal/SecurityLogging.swift
ShadowHarness_FILES += $(SWIFTYJBD_DIR)/JailBreak.swift
ShadowHarness_FILES += $(shell find ../../.detector-deps/BATJailbreakGuard/Sources/BATJailbreakGuard -name '*.swift' | sort)
ShadowHarness_CFLAGS = -fobjc-arc -fmodules-cache-path=/tmp/shadow-harness-module-cache -DSHADOW_HARNESS -DSHDW_DYLDPROBE_EMBEDDED -DSHDW_EMBEDDED_DETECTORS -I../detectors -I../../src/Shadow.framework/Headers
ShadowHarness_CFLAGS += -I$(DTT_DIR)/include -I$(JAILMONKEY_DIR) -I$(ISJB_DIR) -I$(ROOTHIDER_DIR) -Istubs -I$(SAFETYNET_OBJC_DIR) -I$(SAFETYNET_OBJC_DIR)/include -I$(THEOS_PROJECT_DIR)
ShadowHarness_CFLAGS += -F$(FW_LIB_DIR)
ShadowHarness_SWIFTFLAGS = -swift-version 5 -module-cache-path /tmp/shadow-harness-swift-module-cache -F$(TALSEC_FW_DIR) -I$(SAFETYNET_OBJC_DIR) -I$(SAFETYNET_OBJC_DIR)/include -Xcc -I$(SAFETYNET_OBJC_DIR)/include -Xcc -Wno-error=unknown-warning-option -Xcc -Wno-error=incomplete-umbrella
ShadowHarness_SWIFT_BRIDGING_HEADER = ShadowHarness-Bridging.h
ShadowHarness_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowHarness_LDFLAGS += -F../../src/ -F../../vendor/ -F$(TALSEC_FW_DIR) -F$(FW_LIB_DIR)
ShadowHarness_LDFLAGS += -framework TalsecRuntime -lswiftFoundation -rpath @executable_path/Frameworks -rpath @loader_path/Frameworks
ShadowHarness_EXTRA_FRAMEWORKS = Shadow IOSSecuritySuite JailbreakDetector SecurityToolkit BATJailbreakGuard DeviceSecurityKit
ShadowHarness_FRAMEWORKS = UIKit Foundation Security LocalAuthentication DeviceCheck CFNetwork CryptoKit
ShadowHarness_CODESIGN_FLAGS = -SResources/ShadowHarness.entitlements
ShadowHarness_INSTALL_PATH = /Applications
ShadowHarness_RESOURCE_DIRS = Resources

include $(THEOS_MAKE_PATH)/application.mk

before-all::
	$(ECHO_NOTHING)mkdir -p /tmp/shadow-harness-compat-frameworks$(ECHO_END)
	$(ECHO_NOTHING)ln -sfn "$(THEOS)/sdks/iPhoneOS14.5.sdk/System/Library/Frameworks/Foundation.framework" /tmp/shadow-harness-compat-frameworks/Foundation.framework$(ECHO_END)

before-stage::
	$(ECHO_NOTHING)rm -rf \
		"$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks" \
		"$(THEOS_STAGING_DIR)/Applications/dyldprobe.app"$(ECHO_END)

after-stage::
	$(ECHO_NOTHING)test -f "$(SHDW_DYLDPROBE_OBJ_DIR)/shdwtestlib.dylib" || exit 1; \
	mkdir -p "$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks"; \
	cp "$(SHDW_DYLDPROBE_OBJ_DIR)/shdwtestlib.dylib" \
		"$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"; \
	cp -R "$(TALSEC_FW_DIR)/TalsecRuntime.framework" \
		"$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"; \
	$(TARGET_CODESIGN) -S \
		"$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/TalsecRuntime.framework/TalsecRuntime"; \
	for fw in IOSSecuritySuite JailbreakDetector SecurityToolkit BATJailbreakGuard DeviceSecurityKit; do \
		cp -R "$(FW_LIB_DIR)/$$fw.framework" \
			"$(THEOS_STAGING_DIR)/Applications/ShadowHarness.app/Frameworks/"; \
	done$(ECHO_END)
