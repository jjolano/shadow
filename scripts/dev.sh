#!/usr/bin/env bash
# Run a script (from stdin) as root on the test device.
# Device address and credentials come from the environment: this file is public
# and must carry no device detail.
set -euo pipefail
: "${SHADOW_DEV_HOST:?set SHADOW_DEV_HOST to user@host for the test device}"
: "${SHADOW_DEV_PASS:?set SHADOW_DEV_PASS for the test device}"
HOST=$SHADOW_DEV_HOST
PASS=$SHADOW_DEV_PASS
# Unique remote path: concurrent invocations must not clobber each other's
# staged script (a fixed name races two callers onto one file).
# The password never enters a command line: sshpass reads it from the
# environment (-e), and it reaches the remote as the first stdin line, which
# is handed to `sudo -S` from a shell builtin. No askpass file is staged.
RID="$$.${RANDOM}${RANDOM}"
{ printf '%s\n' "$PASS"; cat; } | SSHPASS=$PASS sshpass -e ssh \
  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no "$HOST" \
  "umask 077
IFS= read -r pw
cat > /tmp/.dev_run.$RID
sh=\$(command -v sh)
printf '%s\n' \"\$pw\" | sudo -S -p '' \"\$sh\" /tmp/.dev_run.$RID
rc=\$?
rm -f /tmp/.dev_run.$RID
exit \$rc"
