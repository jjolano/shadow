ARCHS = armv7 armv7s arm64 arm64e
TARGET = iphone:clang:14.5:8.0

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += fmwk
SUBPROJECTS += dylib
SUBPROJECTS += preferencebundle
SUBPROJECTS += shdw
include $(THEOS_MAKE_PATH)/aggregate.mk
