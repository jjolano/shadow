#!/usr/bin/env bash
# Run a script (from stdin) as root on the test device.
# Device address and credentials come from the environment: this file is public
# and must carry no device detail.
set -euo pipefail
: "${SHADOW_DEV_HOST:?set SHADOW_DEV_HOST to user@host for the test device}"
: "${SHADOW_DEV_PASS:?set SHADOW_DEV_PASS for the test device}"
HOST=$SHADOW_DEV_HOST
PASS=$SHADOW_DEV_PASS
# Unique remote paths: concurrent invocations must not clobber each other's
# staged script (fixed names race two callers onto one file).
RID="$$.${RANDOM}${RANDOM}"
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no "$HOST" \
  "cat > /tmp/.dev_askpass.$RID <<'AP'
#!/var/jb/bin/sh
echo $PASS
AP
chmod +x /tmp/.dev_askpass.$RID
cat > /tmp/.dev_run.$RID
SUDO_ASKPASS=/tmp/.dev_askpass.$RID sudo -A /var/jb/bin/sh /tmp/.dev_run.$RID
rc=\$?
rm -f /tmp/.dev_askpass.$RID /tmp/.dev_run.$RID
exit \$rc"
