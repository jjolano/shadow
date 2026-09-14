# Shadow's build-lane matrix. The fields every project targeting a lane must
# agree on -- ARCHS, TARGET, SCHEME, DEPLOY, DEPLOY_ARM64E, ABI -- come from
# $THEOS/bin/lane.sh so Shadow and HookKit cannot drift apart. Only Shadow's own
# packaging identity and firmware limits are defined here.
#
# Sourced by .github/scripts/build-deps.sh and build.sh; the root Makefile reads
# the same fields via $(shell). Consumers must read these fields rather than
# duplicate package limits.

. "${THEOS:?THEOS must point to Theos}/bin/lane.sh"

shadow_lane_field() { # <lane> <field>
    # Shared fields are Theos's; only Shadow-specific ones are answered here.
    case "$2" in
    FLOOR|CEILING|PACKAGE|PACKAGE_ARCH) ;;
    *) theos_lane_field "$1" "$2"; return ;;
    esac
    case "$1:$2" in
    rootful-legacy:FLOOR)         echo "9.0" ;;
    rootful-legacy:CEILING)       echo "14.0" ;;
    rootful-legacy:PACKAGE)       echo "me.jjolano.shadow.legacy" ;;
    rootful-legacy:PACKAGE_ARCH)  echo "iphoneos-arm" ;;
    rootful-modern:FLOOR)         echo "14.0" ;;
    rootful-modern:CEILING)       echo "" ;;
    rootful-modern:PACKAGE)       echo "me.jjolano.shadow" ;;
    rootful-modern:PACKAGE_ARCH)  echo "iphoneos-arm" ;;
    rootless:FLOOR)               echo "15.0" ;;
    rootless:CEILING)             echo "" ;;
    rootless:PACKAGE)             echo "me.jjolano.shadow" ;;
    rootless:PACKAGE_ARCH)        echo "iphoneos-arm64" ;;
    roothide:FLOOR)               echo "15.0" ;;
    roothide:CEILING)             echo "18.0" ;;
    roothide:PACKAGE)             echo "me.jjolano.shadow" ;;
    roothide:PACKAGE_ARCH)        echo "iphoneos-arm64e" ;;
    *) echo "unknown lane '$1' or field '$2'" >&2; return 1 ;;
    esac
}
