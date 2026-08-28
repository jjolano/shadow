#!/usr/bin/env bash
# Provision the pinned HookKit into $THEOS for one Shadow lane. HookKit is
# consumed from the Theos install (see hookkit.mk), not vendored, so CI runs
# this before build-deps.sh/build.sh. Local developers manage their own Theos
# HookKit (HookKit repo: make install-theos) and do not need this.
set -euo pipefail

LANE=${1:?usage: install-hookkit-theos.sh <rootful-legacy|rootful-modern|rootless|roothide>}
: "${THEOS:?THEOS must be set}"
: "${HOOKKIT:?HOOKKIT pin must be set}"

WORK=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hookkit-theos.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# Prefer a local co-dev checkout (DEPS_SOURCE_ROOT/HookKit) so an unpushed pin
# resolves; otherwise clone the public repo. A pinned SHA can be unreachable
# from any ref (rewritten history), so fall back to fetch-by-SHA.
src=${DEPS_SOURCE_ROOT:-}/HookKit
if [ -d "$src/.git" ]; then
    git clone --quiet "$src" "$WORK/hookkit"
else
    git clone --quiet https://github.com/jjolano/HookKit "$WORK/hookkit"
fi
git -C "$WORK/hookkit" checkout --quiet --detach "$HOOKKIT" 2>/dev/null || {
    git -C "$WORK/hookkit" fetch --quiet origin "$HOOKKIT"
    git -C "$WORK/hookkit" checkout --quiet --detach FETCH_HEAD
}

# Build and stage just this lane's framework into $THEOS at the location
# hookkit.mk resolves. install-theos.sh owns the lane -> path layout.
bash "$WORK/hookkit/scripts/install-theos.sh" "$LANE"
echo "provisioned HookKit ($HOOKKIT) for $LANE into $THEOS"
