#!/usr/bin/env bash
# Removes the MNSCloud access connector from this host: service, timer, key, configuration, runtime
# and the system user. Afterwards delete (or disable) the connector in the App as well: this
# script cannot reach the platform. Deno is left installed.
set -Eeuo pipefail
CONNECTOR_APP_DIR="/opt/mnscloud-access-connector"
CONNECTOR_CONF_DIR="/etc/mnscloud-access-connector"
CONNECTOR_USER="mns-connector"
[[ "$EUID" -eq 0 ]] || { printf 'run this command with sudo\n' >&2; exit 1; }
systemctl disable --now mnscloud-access-connector-update.timer mnscloud-access-connector.service >/dev/null 2>&1 || true
systemctl stop mnscloud-access-connector-update.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/mnscloud-access-connector.service \
 /etc/systemd/system/mnscloud-access-connector-update.service \
 /etc/systemd/system/mnscloud-access-connector-update.timer
systemctl daemon-reload
rm -rf "$CONNECTOR_CONF_DIR" "$CONNECTOR_APP_DIR" /var/cache/mnscloud-access-connector /var/cache/mnscloud-access-connector-root
if id -u "$CONNECTOR_USER" >/dev/null 2>&1; then userdel "$CONNECTOR_USER" >/dev/null 2>&1 || true; fi
printf '[mnscloud-access-connector] removed; delete the connector in the App (Rede > Conectores) too\n'
