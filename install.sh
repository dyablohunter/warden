#!/usr/bin/env bash
# Install Warden on Ubuntu (26.04 LTS; works on 22.04+). Run as root from the repo checkout:
#   sudo ./install.sh [--extras]
#   --extras  also install lynis, debsums, needrestart, smartmontools for deeper audits
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX=/opt/warden
CONF_DIR=/etc/warden
CONF=$CONF_DIR/warden.env
STATE=/var/lib/warden
EXTRAS=0
[[ "${1:-}" == "--extras" ]] && EXTRAS=1

[[ $EUID -eq 0 ]] || { echo "run as root (sudo ./install.sh)"; exit 1; }
grep -qi ubuntu /etc/os-release || echo "warning: this is not Ubuntu; continuing anyway"

echo "==> installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 nftables iproute2 ca-certificates >/dev/null
if [[ $EXTRAS -eq 1 ]]; then
  apt-get install -y -qq lynis debsums needrestart smartmontools >/dev/null || true
fi

python3 - <<'EOF'
import sys
if sys.version_info < (3, 10):
    sys.exit("Python >= 3.10 required")
EOF

echo "==> copying code to $PREFIX"
install -d -m 0755 "$PREFIX"
rm -rf "$PREFIX/warden"
cp -r "$SRC/warden" "$PREFIX/"
find "$PREFIX" -name '__pycache__' -prune -exec rm -rf {} +
chown -R root:root "$PREFIX"
chmod -R go-w "$PREFIX"

echo "==> config in $CONF"
install -d -m 0700 "$CONF_DIR"
if [[ ! -f "$CONF" ]]; then
  if [[ -f "$SRC/.env" ]]; then
    # start from the full example, then overlay the values from the repo .env
    cp "$SRC/.env.example" "$CONF"
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ "$line" =~ ^[[:space:]]*# || -z "${line// }" ]] && continue
      key="${line%%=*}"; key="${key// /}"
      if grep -qE "^#?[[:space:]]*${key}=" "$CONF"; then
        python3 - "$CONF" "$key" "$line" <<'EOF'
import re, sys
path, key, line = sys.argv[1:]
text = open(path).read()
text = re.sub(rf"^#?\s*{re.escape(key)}=.*$", lambda m: line, text, count=1, flags=re.M)
open(path, "w").write(text)
EOF
      else
        echo "$line" >> "$CONF"
      fi
    done < "$SRC/.env"
    echo "    created from .env.example + your .env"
  else
    cp "$SRC/.env.example" "$CONF"
    echo "    created from .env.example — EDIT IT (API key, email)"
  fi
else
  echo "    exists, leaving it untouched"
fi
chmod 600 "$CONF"

# Protect the operator: allowlist the IP of the SSH session running this installer.
ADMIN_IP="${SSH_CLIENT%% *}"
if [[ -n "${ADMIN_IP}" ]] && ! grep -qE "^WARDEN_ALLOWLIST=.*${ADMIN_IP//./\\.}" "$CONF"; then
  if grep -qE '^WARDEN_ALLOWLIST=' "$CONF"; then
    sed -i -E "s|^WARDEN_ALLOWLIST=\"?([^\"]*)\"?$|WARDEN_ALLOWLIST=\"\1 ${ADMIN_IP}\"|" "$CONF"
  else
    echo "WARDEN_ALLOWLIST=\"${ADMIN_IP}\"" >> "$CONF"
  fi
  echo "    added your current SSH client IP ${ADMIN_IP} to WARDEN_ALLOWLIST"
fi

install -d -m 0700 "$STATE"

echo "==> CLI wrapper /usr/local/bin/warden"
cat > /usr/local/bin/warden <<'EOF'
#!/bin/sh
export WARDEN_ENV_FILE="${WARDEN_ENV_FILE:-/etc/warden/warden.env}"
export PYTHONPATH=/opt/warden
exec /usr/bin/python3 -s -m warden "$@"
EOF
chmod 0755 /usr/local/bin/warden

echo "==> systemd unit"
install -m 0644 "$SRC/systemd/warden.service" /etc/systemd/system/warden.service
systemctl daemon-reload

echo "==> checks"
warden check || true
echo
if warden test-llm; then
  systemctl enable --now warden
  systemctl restart warden
  echo
  echo "Warden is running.  Useful commands:"
  echo "  warden status            journalctl -u warden -f"
  echo "  warden test-email        warden ask \"audit this server\""
else
  echo "LLM test failed — fix $CONF, then: systemctl enable --now warden"
fi
