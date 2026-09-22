#!/usr/bin/env bash
# Build the frontend and install richrule to /opt/richrule as a systemd service.
set -euo pipefail

PREFIX=${PREFIX:-/opt/richrule}
SRC=$(cd "$(dirname "$0")/.." && pwd)

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo $0)" >&2
  exit 1
fi

rpm -q python3-firewall python3-dbus >/dev/null || dnf install -y python3-firewall python3-dbus

echo "==> building frontend"
# Build as the invoking user so node_modules is not root-owned. Use a login shell (-i):
# sudo resets PATH, which hides per-user node installs (e.g. ~/.local/bin, nvm).
BUILD_USER=${SUDO_USER:-root}
if sudo -u "$BUILD_USER" -i bash -c 'command -v npm >/dev/null'; then
  sudo -u "$BUILD_USER" -i bash -c "cd '$SRC/frontend' && npm ci && npm run build"
elif [[ -f "$SRC/frontend/dist/index.html" ]]; then
  echo "    npm not found for $BUILD_USER; using existing build in frontend/dist" >&2
else
  echo "npm not found. Build the frontend first (cd frontend && npm ci && npm run build)" \
    "or set PATH so '$BUILD_USER' can run npm, then re-run." >&2
  exit 1
fi

echo "==> installing to $PREFIX"
mkdir -p "$PREFIX/backend" "$PREFIX/frontend"
cp -r "$SRC/backend/app" "$SRC/backend/pyproject.toml" "$PREFIX/backend/"
rm -rf "$PREFIX/frontend/dist"
cp -r "$SRC/frontend/dist" "$PREFIX/frontend/dist"

if [[ ! -x "$PREFIX/backend/.venv/bin/python" ]]; then
  python3 -m venv --system-site-packages "$PREFIX/backend/.venv"
fi
"$PREFIX/backend/.venv/bin/pip" install -q --upgrade "$PREFIX/backend"

install -m 0644 "$SRC/deploy/pam.d-richrule" /etc/pam.d/richrule
install -m 0644 "$SRC/deploy/richrule.service" /etc/systemd/system/richrule.service
systemctl daemon-reload
systemctl enable --now richrule
systemctl restart richrule

echo "==> richrule is listening on 127.0.0.1:8443"
echo "    remote access: ssh -L 8443:127.0.0.1:8443 $(hostname)  then open http://localhost:8443"
