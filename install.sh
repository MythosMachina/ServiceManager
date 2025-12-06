#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/service-manager}"
SERVICE_NAME="${SERVICE_NAME:-service-webui}"
ACCESS_GROUP="${ACCESS_GROUP:-svcweb}"
PORT="${PORT:-3001}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root or via sudo."
  exit 1
fi

echo ">> Target directory: $APP_DIR"
mkdir -p "$APP_DIR"

echo ">> Copying application..."
cp -r app.js package.json package-lock.json public "$APP_DIR"/

echo ">> npm ci (no dev dependencies)..."
cd "$APP_DIR"
npm ci --omit=dev

echo ">> Ensure group exists: $ACCESS_GROUP"
if ! getent group "$ACCESS_GROUP" >/dev/null; then
  groupadd "$ACCESS_GROUP"
fi

DEFAULT_ENV="/etc/default/${SERVICE_NAME}"
if [[ ! -f "$DEFAULT_ENV" ]]; then
  echo ">> Creating $DEFAULT_ENV"
  SESSION_SECRET="$(openssl rand -hex 32)"
  cat > "$DEFAULT_ENV" <<EOF
PORT=${PORT}
ACCESS_GROUP=${ACCESS_GROUP}
SESSION_SECRET=${SESSION_SECRET}
EOF
fi

echo ">> Installing systemd unit"
cp "$(dirname "$0")/service-webui.service" "/etc/systemd/system/${SERVICE_NAME}.service"
sed -i "s#/opt/service-manager#${APP_DIR}#g" "/etc/systemd/system/${SERVICE_NAME}.service"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

echo ">> Done. Service running on port ${PORT}. Group: ${ACCESS_GROUP}"
echo "Grant access: usermod -aG ${ACCESS_GROUP} <username>"
