# Service Manager (Non-Native systemd Services)

Web-based service manager with PAM login and group gating; lists non-native systemd services and allows start/stop/restart.
<img width="1147" height="864" alt="grafik" src="https://github.com/user-attachments/assets/81bf0467-cd34-42f9-bc2a-a8842d0c5436" />

## What it does
- Authenticates against local users via PAM; access is limited to a Unix group (default `svcweb`).
- Hides Ubuntu/native services using package priority, prefixes, and allowlists; shows custom/optional services.
- Dark UI with search, favorites (stored in browser), and start/stop/restart actions.
- Ships with systemd unit, installer, and group/user helper.

## Requirements
- Systemd-based Linux, root/sudo privileges.
- Node.js and npm available (installer runs `npm ci --omit=dev`).

## Quick install
```bash
sudo ./install.sh
```
Defaults (override via env):
- `APP_DIR=/opt/service-manager`
- `SERVICE_NAME=service-webui`
- `PORT=3001`
- `ACCESS_GROUP=svcweb`

What the installer does:
1) Copies the app to APP_DIR and runs `npm ci --omit=dev`.
2) Ensures the access group exists.
3) Creates `/etc/default/service-webui` with PORT/ACCESS_GROUP/SESSION_SECRET if missing.
4) Installs the systemd unit, reloads daemon, enables and starts the service.

## Add users to the access group
Use the helper to add existing (or create new) users to the group:
```bash
sudo ./setup.sh
```
You will be prompted for usernames; leave empty to finish. Non-existing users can be created on the fly (disabled-password).

## Usage
- UI: `http://<host>:PORT`
- Login with any local account that is in the access group.
- Filter services with the search field; pin favorites via the star icon to keep them on top.

## License
MIT © MythosMachina — https://github.com/MythosMachina/ServiceManager
