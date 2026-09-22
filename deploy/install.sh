#!/usr/bin/env bash
# Build the frontend and install richrule to /opt/richrule as a systemd service.
#
#   sudo ./install.sh                 # localhost only, plain HTTP (use an SSH tunnel)
#   sudo ./install.sh --tls           # also generate a self-signed certificate and serve HTTPS
#   sudo ./install.sh --tls --listen 0.0.0.0   # reachable from the network (e.g. as an agent)
#
# Settings live in /etc/richrule/richrule.env (created on first install, never overwritten).
set -euo pipefail

PREFIX=${PREFIX:-/opt/richrule}
SRC=$(cd "$(dirname "$0")/.." && pwd)
ENV_FILE=/etc/richrule/richrule.env
TLS=0
LISTEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tls) TLS=1 ;;
    --listen) LISTEN=${2:?--listen needs an address}; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo $0)" >&2
  exit 1
fi

rpm -q python3-firewall python3-dbus git-core >/dev/null 2>&1 || dnf install -y python3-firewall python3-dbus git-core

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
rm -rf "$PREFIX/backend/app"
cp -r "$SRC/backend/app" "$SRC/backend/pyproject.toml" "$PREFIX/backend/"
rm -rf "$PREFIX/frontend/dist"
cp -r "$SRC/frontend/dist" "$PREFIX/frontend/dist"

if [[ ! -x "$PREFIX/backend/.venv/bin/python" ]]; then
  python3 -m venv --system-site-packages "$PREFIX/backend/.venv"
fi
"$PREFIX/backend/.venv/bin/pip" install -q --upgrade "$PREFIX/backend"

# -- configuration ------------------------------------------------------------------
install -d -m 0750 /etc/richrule
if [[ ! -f $ENV_FILE ]]; then
  install -m 0640 "$SRC/deploy/richrule.env" "$ENV_FILE"
fi

set_env() {  # set_env KEY VALUE: replace or append in the env file
  if grep -qE "^#?\s*$1=" "$ENV_FILE"; then
    sed -i -E "s|^#?\s*$1=.*|$1=$2|" "$ENV_FILE"
  else
    echo "$1=$2" >>"$ENV_FILE"
  fi
}

if [[ $TLS -eq 1 ]]; then
  TLS_DIR=/etc/richrule/tls
  install -d -m 0700 "$TLS_DIR"
  if [[ ! -f $TLS_DIR/cert.pem ]]; then
    echo "==> generating a self-signed certificate for $(hostname -f 2>/dev/null || hostname)"
    FQDN=$(hostname -f 2>/dev/null || hostname)
    openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 \
      -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" -subj "/CN=$FQDN" \
      -addext "subjectAltName=DNS:$FQDN,DNS:$(hostname -s),DNS:localhost,IP:127.0.0.1" 2>/dev/null
    chmod 0600 "$TLS_DIR/key.pem"
  fi
  set_env RICHRULE_TLS_CERT "$TLS_DIR/cert.pem"
  set_env RICHRULE_TLS_KEY "$TLS_DIR/key.pem"
fi
if [[ -n $LISTEN ]]; then
  set_env RICHRULE_HOST "$LISTEN"
fi

install -m 0644 "$SRC/deploy/pam.d-richrule" /etc/pam.d/richrule
install -m 0644 "$SRC/deploy/richrule.service" /etc/systemd/system/richrule.service
systemctl daemon-reload
systemctl enable --now richrule
systemctl restart richrule

# shellcheck disable=SC1090
source "$ENV_FILE"
SCHEME=http
[[ -n ${RICHRULE_TLS_CERT:-} ]] && SCHEME=https
HOST=${RICHRULE_HOST:-127.0.0.1}
PORT=${RICHRULE_PORT:-8443}
echo "==> richrule is listening on $SCHEME://$HOST:$PORT (settings: $ENV_FILE)"
if [[ $HOST == 127.0.0.1 || $HOST == localhost ]]; then
  echo "    remote access: ssh -L $PORT:127.0.0.1:$PORT $(hostname)  then open $SCHEME://localhost:$PORT"
else
  echo "    make sure port $PORT/tcp is allowed only from trusted networks, e.g. a rich rule:"
  echo "    rule family=\"ipv4\" source address=\"<admin-network>\" port port=\"$PORT\" protocol=\"tcp\" accept"
fi
if [[ $SCHEME == https && -f /etc/richrule/tls/cert.pem ]]; then
  echo "    certificate (paste into a console's Hosts page as custom CA): /etc/richrule/tls/cert.pem"
fi
