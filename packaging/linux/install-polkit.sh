#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "install-polkit.sh must run as root" >&2
  exit 2
fi

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIRECTORY=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/../.." && pwd)
RUNTIME_DIRECTORY=/opt/continuum-memory-polkit
HELPER_DIRECTORY=/usr/libexec/continuum-memory
POLICY_DIRECTORY=/usr/share/polkit-1/actions

if [ ! -x /usr/bin/pkexec ] || [ ! -x /usr/bin/openssl ]; then
  echo "pkexec and OpenSSL are required at their system paths" >&2
  exit 2
fi

python3 -m venv "$RUNTIME_DIRECTORY"
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
  "$RUNTIME_DIRECTORY/bin/python" -m pip install --no-cache-dir --no-deps "$SOURCE_DIRECTORY"
chown -R root:root "$RUNTIME_DIRECTORY"
chmod -R go-w "$RUNTIME_DIRECTORY"

install -d -o root -g root -m 0755 "$HELPER_DIRECTORY"
install -o root -g root -m 0755 "$SCRIPT_DIRECTORY/approval-helper" \
  "$HELPER_DIRECTORY/approval-helper"
install -o root -g root -m 0644 "$SCRIPT_DIRECTORY/org.continuummemory.approval.policy" \
  "$POLICY_DIRECTORY/org.continuummemory.approval.policy"

echo "Installed the Continuum Memory polkit helper."
echo "Start memoryd, then run: continuum approval provision-linux"
