#!/usr/bin/env bash
# Run a script (from stdin) as root on the test device.
set -euo pipefail
HOST=${SHADOW_DEV_HOST:-mobile@10.0.1.160}
PASS=${SHADOW_DEV_PASS:-alpine}
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no "$HOST" \
  "cat > /tmp/.dev_askpass.sh <<'AP'
#!/var/jb/bin/sh
echo $PASS
AP
chmod +x /tmp/.dev_askpass.sh
cat > /tmp/.dev_run.sh
SUDO_ASKPASS=/tmp/.dev_askpass.sh sudo -A /var/jb/bin/sh /tmp/.dev_run.sh"
