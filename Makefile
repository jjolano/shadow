ARCHS = armv7 arm64 arm64e
TARGET = iphone:clang:13.0:7.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += dylib
SUBPROJECTS += preferencebundle
include $(THEOS_MAKE_PATH)/aggregate.mk
