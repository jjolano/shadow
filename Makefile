# Defaults for bare `make` without a lane; lane builds override below.
ARCHS ?= arm64 arm64e
TARGET ?= iphone:clang:16.5:12.0

# Lane matrix lives in one place; see lanes.sh. The shell file is the
# single source of truth — make reads fields through it so the two can
# never drift.
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

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += Shadow.framework
SUBPROJECTS += Shadow.dylib
SUBPROJECTS += ShadowCore.dylib
SUBPROJECTS += ShadowSettings.bundle
SUBPROJECTS += shdw
include $(THEOS_MAKE_PATH)/aggregate.mk

# The rootless scheme stages the whole layout/ under /var/jb. Select the
# matching ruleset-watcher plist after staging, before packaging.
before-package::
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.plist"$(ECHO_END)
	$(ECHO_NOTHING)test -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist" && mv "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.plist" || true$(ECHO_END)
else
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.jjolano.shadow.watcher.rootless.plist"$(ECHO_END)
endif
