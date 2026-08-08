# shadowd — root LaunchDaemon owning all vnode-layer kernel read/write for
# Shadow.  Plain ObjC/C, no Logos, no tweak headers.  arm64/arm64e only —
# both krw backends (tfp0 pfinder, libjailbreak PPL) are 64-bit-kernel
# code; the fat rootful pass builds all other subprojects for
# armv7/armv7s too, so override pins the slices the parent ARCHS would
# otherwise leak in (postinst strips shadowd on 32-bit devices).
#
# Build (rootless, iOS 15.0 floor):
#   THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" \
#     TARGET=iphone:clang:latest:15.0 make -C shadowd
#
# INSTALL_PATH /usr/libexec → /var/jb/usr/libexec/shadowd under the rootless
# scheme, /usr/libexec/shadowd on rootful (packaging lane wires the
# launchd plist).

override ARCHS := arm64 arm64e
TARGET ?= iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = shadowd

shadowd_FILES = main.m krw.m ledger.m
shadowd_CFLAGS = -fobjc-arc
shadowd_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
shadowd_INSTALL_PATH = /usr/libexec
shadowd_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tool.mk
