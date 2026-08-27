# Single source of truth for Shadow's build-lane matrix. Sourced by
# .github/scripts/build-deps.sh and build.sh; the root Makefile reads the
# same fields via $(shell). Fields: ARCHS, TARGET, SCHEME, FLOOR, CEILING,
# DEPLOY, DEPLOY_ARM64E, PACKAGE, PACKAGE_ARCH (the deployment fields only
# apply where they are non-empty).
#
# Consumers must read these fields rather than duplicate package limits.

shadow_lane_field() { # <lane> <field>
    case "$1:$2" in
    rootful-legacy:ARCHS)         echo "armv7 armv7s arm64 arm64e" ;;
    rootful-legacy:TARGET)        echo "iphone:clang:13.7" ;;
    rootful-legacy:SCHEME)        echo "" ;;
    rootful-legacy:FLOOR)         echo "9.0" ;;
    rootful-legacy:CEILING)       echo "14.0" ;;
    rootful-legacy:DEPLOY)        echo "9.0" ;;
    rootful-legacy:DEPLOY_ARM64E) echo "12.0" ;;
    rootful-legacy:PACKAGE)       echo "me.jjolano.shadow.legacy" ;;
    rootful-legacy:PACKAGE_ARCH)  echo "iphoneos-arm" ;;
    rootful-modern:ARCHS)         echo "arm64 arm64e" ;;
    rootful-modern:TARGET)        echo "iphone:clang:16.5:14.0" ;;
    rootful-modern:SCHEME)        echo "" ;;
    rootful-modern:FLOOR)         echo "14.0" ;;
    rootful-modern:CEILING)       echo "" ;;
    rootful-modern:DEPLOY)        echo "" ;;
    rootful-modern:DEPLOY_ARM64E) echo "" ;;
    rootful-modern:PACKAGE)       echo "me.jjolano.shadow" ;;
    rootful-modern:PACKAGE_ARCH)  echo "iphoneos-arm" ;;
    rootless:ARCHS)               echo "arm64 arm64e" ;;
    rootless:TARGET)              echo "iphone:clang:16.5:15.0" ;;
    rootless:SCHEME)              echo "rootless" ;;
    rootless:FLOOR)               echo "15.0" ;;
    rootless:CEILING)             echo "" ;;
    rootless:DEPLOY)              echo "" ;;
    rootless:DEPLOY_ARM64E)       echo "" ;;
    rootless:PACKAGE)             echo "me.jjolano.shadow" ;;
    rootless:PACKAGE_ARCH)        echo "iphoneos-arm64" ;;
    roothide:ARCHS)               echo "arm64 arm64e" ;;
    roothide:TARGET)              echo "iphone:clang:16.5:15.0" ;;
    roothide:SCHEME)              echo "roothide" ;;
    roothide:FLOOR)               echo "15.0" ;;
    roothide:CEILING)             echo "18.0" ;;
    roothide:DEPLOY)              echo "" ;;
    roothide:DEPLOY_ARM64E)       echo "" ;;
    roothide:PACKAGE)             echo "me.jjolano.shadow" ;;
    roothide:PACKAGE_ARCH)        echo "iphoneos-arm64e" ;;
    *) echo "unknown lane '$1' or field '$2'" >&2; return 1 ;;
    esac
}

# CLI mode for make $(shell): lanes.sh get <lane> <field>
if [ "${1:-}" = get ] && [ "$#" -eq 3 ]; then
    shadow_lane_field "$2" "$3"
fi
