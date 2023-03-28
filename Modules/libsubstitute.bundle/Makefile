ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:14.5:8.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitSubstituteModule
HookKitSubstituteModule_BUNDLE_EXTENSION = bundle
HookKitSubstituteModule_FILES = Module.m HKSubstitute.m
HookKitSubstituteModule_LIBRARIES = _substitute
HookKitSubstituteModule_EXTRA_FRAMEWORKS = HookKit _CydiaSubstrate
HookKitSubstituteModule_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitSubstituteModule_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitSubstituteModule_LDFLAGS += -Fvendor -Lvendor/substitute
HookKitSubstituteModule_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
