ARCHS := armv7 armv7s arm64 arm64e
TARGET := iphone:clang:11.2:8.0

ifeq ($(DEBUG),)
CLASS_NAME := $(shell openssl rand -hex 8)
FUNC_GEN_DYLD := $(shell openssl rand -hex 8)
FUNC_GEN_FMAP := $(shell openssl rand -hex 8)
FUNC_GEN_URL := $(shell openssl rand -hex 8)
FUNC_GEN_ERR := $(shell openssl rand -hex 8)
FUNC_RESTRICT_IMAGE := $(shell openssl rand -hex 8)
FUNC_RESTRICT_PATH := $(shell openssl rand -hex 8)
FUNC_RESTRICT_URL := $(shell openssl rand -hex 8)
FUNC_ADD_PATH := $(shell openssl rand -hex 8)
FUNC_ADD_RESTRICT_PATH := $(shell openssl rand -hex 8)
FUNC_ADD_FILE_MAP := $(shell openssl rand -hex 8)
FUNC_ADD_SCHEMES := $(shell openssl rand -hex 8)
FUNC_ADD_LINK := $(shell openssl rand -hex 8)
FUNC_RESOLVE_LINK := $(shell openssl rand -hex 8)
endif

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = _Shadow
$(TWEAK_NAME)_FILES = Classes/Shadow.xm Tweak.xm
$(TWEAK_NAME)_EXTRA_FRAMEWORKS = Cephei
$(TWEAK_NAME)_CFLAGS = -fobjc-arc

# Obfuscation for final builds
ifeq ($(DEBUG),)
$(TWEAK_NAME)_CFLAGS += -DShadow=_$(CLASS_NAME)
$(TWEAK_NAME)_CFLAGS += -DgenerateDyldArray=_$(FUNC_GEN_DYLD)
$(TWEAK_NAME)_CFLAGS += -DgenerateFileMap=_$(FUNC_GEN_FMAP)
$(TWEAK_NAME)_CFLAGS += -DgenerateSchemeArray=_$(FUNC_GEN_URL)
$(TWEAK_NAME)_CFLAGS += -DgenerateFileNotFoundError=_$(FUNC_GEN_ERR)
$(TWEAK_NAME)_CFLAGS += -DisImageRestricted=_$(FUNC_RESTRICT_IMAGE)
$(TWEAK_NAME)_CFLAGS += -DisPathRestricted=_$(FUNC_RESTRICT_PATH)
$(TWEAK_NAME)_CFLAGS += -DisURLRestricted=_$(FUNC_RESTRICT_URL)
$(TWEAK_NAME)_CFLAGS += -DaddPath=_$(FUNC_ADD_PATH)
$(TWEAK_NAME)_CFLAGS += -DaddRestrictedPath=_$(FUNC_ADD_RESTRICT_PATH)
$(TWEAK_NAME)_CFLAGS += -DaddPathsFromFileMap=_$(FUNC_ADD_FILE_MAP)
$(TWEAK_NAME)_CFLAGS += -DaddSchemesFromURLSet=_$(FUNC_ADD_SCHEMES)
$(TWEAK_NAME)_CFLAGS += -DaddLinkFromPath=_$(FUNC_ADD_LINK)
$(TWEAK_NAME)_CFLAGS += -DresolveLinkInPath=_$(FUNC_RESOLVE_LINK)
endif

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
SUBPROJECTS += ShadowPreferences
include $(THEOS_MAKE_PATH)/aggregate.mk
