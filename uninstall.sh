#!/usr/bin/env bash
# Remove Warden. Keeps /etc/warden and /var/lib/warden unless --purge is given.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

systemctl disable --now warden 2>/dev/null || true
rm -f /etc/systemd/system/warden.service /usr/local/bin/warden
systemctl daemon-reload
nft delete table inet warden 2>/dev/null || true
rm -rf /opt/warden
rm -f /etc/sysctl.d/90-warden.conf

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /etc/warden /var/lib/warden
  echo "Warden removed (config and state purged)."
else
  echo "Warden removed. Config (/etc/warden) and state (/var/lib/warden) kept; use --purge to delete."
fi
