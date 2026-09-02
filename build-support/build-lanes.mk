# Defaults for direct subproject builds; lane builds override below.
ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:16.5:12.0

LANES_SH := $(addprefix $(dir $(lastword $(MAKEFILE_LIST))),lanes.sh)
lane_field = $(shell . "$(LANES_SH)" && shadow_lane_field $(1) $(2) 2>/dev/null)

ifneq ($(SHADOW_LANE),)
ifeq ($(call lane_field,$(SHADOW_LANE),ARCHS),)
$(error unknown SHADOW_LANE '$(SHADOW_LANE)')
endif

override ARCHS := $(call lane_field,$(SHADOW_LANE),ARCHS)
override TARGET := $(call lane_field,$(SHADOW_LANE),TARGET)
override THEOS_PACKAGE_SCHEME := $(call lane_field,$(SHADOW_LANE),SCHEME)

LANE_DEPLOY := $(call lane_field,$(SHADOW_LANE),DEPLOY)
ifneq ($(LANE_DEPLOY),)
override TARGET_OS_DEPLOYMENT_VERSION := $(LANE_DEPLOY)
endif
LANE_DEPLOY_ARM64E := $(call lane_field,$(SHADOW_LANE),DEPLOY_ARM64E)
ifneq ($(LANE_DEPLOY_ARM64E),)
override TARGET_OS_DEPLOYMENT_VERSION_arm64e := $(LANE_DEPLOY_ARM64E)
endif
endif

export ARCHS TARGET TARGET_OS_DEPLOYMENT_VERSION TARGET_OS_DEPLOYMENT_VERSION_arm64e THEOS_PACKAGE_SCHEME
