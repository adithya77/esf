#!/usr/bin/env bash
# Install the ESF stack as systemd user services: Temporal (docker compose),
# the worker, and the read-only console on 127.0.0.1:7331.
#
# Usage: scripts/install-user-services.sh
#
# Prerequisites: ~/.config/esf/factory.toml (the operator configuration; this
# script never writes or overwrites it), docker, and lingering for the user
# (`loginctl enable-linger "$USER"`) so the services start at boot.
#
# The binary is copied to ~/.local/share/esf/bin/factory, so rebuilding the
# repository does not change what the running service executes until the
# script is run again.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${HOME}/.config/esf/factory.toml"
TOKEN="${HOME}/.config/esf/console.token"
BIN_DIR="${HOME}/.local/share/esf/bin"
UNIT_DIR="${HOME}/.config/systemd/user"

if [ ! -f "${CONFIG}" ]; then
  echo "missing ${CONFIG}; write the operator configuration first (see docs/baseten.md)" >&2
  exit 1
fi
if [ "$(loginctl show-user "${USER}" -p Linger --value 2>/dev/null)" != "yes" ]; then
  echo "warning: lingering is off; services will stop at logout (loginctl enable-linger ${USER})" >&2
fi

make -C "${ROOT}" --no-print-directory build >/dev/null
install -d -m 0700 "${BIN_DIR}" "${UNIT_DIR}"
install -m 0755 "${ROOT}/bin/factory" "${BIN_DIR}/factory.new"
mv -f "${BIN_DIR}/factory.new" "${BIN_DIR}/factory"
"${BIN_DIR}/factory" --config "${CONFIG}" config validate

if [ ! -s "${TOKEN}" ]; then
  (umask 077 && openssl rand -hex 32 > "${TOKEN}")
fi
chmod 600 "${TOKEN}"

for unit in esf-temporal esf-worker esf-console; do
  sed -e "s#@ESF_ROOT@#${ROOT}#g" -e "s#@BIN@#${BIN_DIR}/factory#g" \
    "${ROOT}/deploy/systemd-user/${unit}.service" > "${UNIT_DIR}/${unit}.service"
done
systemctl --user daemon-reload
systemctl --user enable --now esf-temporal.service
systemctl --user enable esf-worker.service esf-console.service
systemctl --user restart esf-worker.service esf-console.service
systemctl --user --no-pager --lines=0 status esf-temporal.service esf-worker.service esf-console.service
