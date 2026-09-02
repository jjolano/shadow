# HookKit resolved from the Theos-installed framework (HookKit repo:
# `make install-theos`), not a vendored copy. rootless/roothide are Theos
# schemes, but legacy and modern-rootful are BOTH the default scheme while
# needing different arm64e ABIs, so map by SHADOW_LANE rather than scheme.
# install-theos lays the frameworks out to match these paths.
ifeq ($(SHADOW_LANE),rootful-legacy)
SHADOW_HOOKKIT_DIR := $(THEOS)/lib/iphone/rootful-legacy
else ifeq ($(SHADOW_LANE),rootless)
SHADOW_HOOKKIT_DIR := $(THEOS)/lib/iphone/rootless
else ifeq ($(SHADOW_LANE),roothide)
SHADOW_HOOKKIT_DIR := $(THEOS)/lib/iphone/roothide
else
SHADOW_HOOKKIT_DIR := $(THEOS)/lib
endif

SHADOW_HOOKKIT_CFLAGS := -I$(SHADOW_HOOKKIT_DIR)/HookKit.framework/Headers
SHADOW_HOOKKIT_LDFLAGS := -F$(SHADOW_HOOKKIT_DIR)
