ARCHS ?= armv7 armv7s arm64 arm64e
TARGET ?= iphone:clang:14.5:5.0

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = HookKit

HookKit_FILES = Core.m Module.m Module+Internal.m Hook.m Compat.m
HookKit_FRAMEWORKS = Foundation
HookKit_EXTRA_FRAMEWORKS = Modulous
HookKit_INSTALL_PATH = /Library/Frameworks
HookKit_CFLAGS = -fobjc-arc -IHeaders -Ivendor/Modulous.framework/Headers
HookKit_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
HookKit_LDFLAGS += -Fvendor

include $(THEOS_MAKE_PATH)/framework.mk
