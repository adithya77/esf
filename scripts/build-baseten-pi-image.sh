#!/usr/bin/env bash
# Build the ESF Pi sandbox image on Baseten from deploy/baseten/Dockerfile.pi.
#
# Usage: scripts/build-baseten-pi-image.sh [image-name]
#
# Reads the Baseten API key from $BASETEN_API_KEY_FILE (default
# ~/.config/esf/baseten-api-key, mode 0600) and never prints it. Only the
# Dockerfile and the committed Pi bundle are uploaded. Prints the immutable
# version tag to pin as baseten.template = "sandbox/<name>:<tag>".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${1:-esf-pi}"
KEY_FILE="${BASETEN_API_KEY_FILE:-${HOME}/.config/esf/baseten-api-key}"

if [ "$(stat -c '%a' "${KEY_FILE}")" != "600" ]; then
  echo "refusing: ${KEY_FILE} must be mode 600" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
cp "${ROOT}/deploy/baseten/Dockerfile.pi" "${STAGE}/Dockerfile"
cp "${ROOT}/agents/pi/dist/pi-runner.mjs" "${ROOT}/agents/pi/dist/THIRD_PARTY_NOTICES.txt" \
   "${ROOT}/agents/pi/inventory.json" "${STAGE}/"
(cd "${ROOT}/agents/pi/dist" && sha256sum -c --quiet SHA256SUMS)

# The Baseten CLI is distributed through Homebrew only; the pinned Python SDK
# performs the same directory build.
BASETEN_API_KEY="$(cat "${KEY_FILE}")" uv run --quiet --no-project --python "$(command -v python3)" \
  --with "baseten==0.14.0" --with "httpx[http2]" \
  python -I "${ROOT}/scripts/baseten-image-push.py" --name "${NAME}" --dir "${STAGE}"
