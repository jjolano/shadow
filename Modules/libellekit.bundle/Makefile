ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = HookKitElleKitModule
HookKitElleKitModule_BUNDLE_EXTENSION = bundle
HookKitElleKitModule_FILES = Module.m HKElleKit.m
HookKitElleKitModule_LIBRARIES = _ellekit
HookKitElleKitModule_EXTRA_FRAMEWORKS = HookKit
HookKitElleKitModule_CFLAGS = -fobjc-arc -Ivendor/HookKit.framework/Headers
HookKitElleKitModule_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKitElleKitModule_LDFLAGS += -Fvendor -Lvendor
HookKitElleKitModule_INSTALL_PATH = /Library/Modulous/HookKit

include $(THEOS_MAKE_PATH)/bundle.mk
