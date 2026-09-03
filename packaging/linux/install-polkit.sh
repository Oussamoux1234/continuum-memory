#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  echo "install-polkit.sh must run as root" >&2
  exit 2
fi

for REQUIRED_EXECUTABLE in \
  /usr/bin/chmod /usr/bin/chown /usr/bin/dirname /usr/bin/env /usr/bin/find \
  /usr/bin/install /usr/bin/mktemp /usr/bin/mv /usr/bin/openssl /usr/bin/pkexec \
  /usr/bin/python3 /usr/bin/readlink /usr/bin/rmdir /usr/bin/rm; do
  if [ ! -x "$REQUIRED_EXECUTABLE" ]; then
    echo "required system executable is unavailable: $REQUIRED_EXECUTABLE" >&2
    exit 2
  fi
done

SCRIPT_PATH=$(/usr/bin/readlink -f -- "$0")
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$SCRIPT_PATH")" && pwd)
SOURCE_DIRECTORY=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/../.." && pwd)
RUNTIME_DIRECTORY=/opt/continuum-memory-polkit
HELPER_DIRECTORY=/usr/libexec/continuum-memory
POLICY_DIRECTORY=/usr/share/polkit-1/actions
BUILD_DIRECTORY=
BACKUP_DIRECTORY=

cleanup() {
  case "$BUILD_DIRECTORY" in
    /opt/.continuum-memory-polkit-build.*)
      /usr/bin/rm -rf -- "$BUILD_DIRECTORY"
      ;;
  esac
  if [ -n "$BACKUP_DIRECTORY" ] && [ -d "$BACKUP_DIRECTORY" ] && \
     [ ! -e "$RUNTIME_DIRECTORY" ] && [ ! -L "$RUNTIME_DIRECTORY" ]; then
    /usr/bin/mv -- "$BACKUP_DIRECTORY" "$RUNTIME_DIRECTORY" || true
  fi
}
trap cleanup 0

BUILD_DIRECTORY=$(/usr/bin/mktemp -d /opt/.continuum-memory-polkit-build.XXXXXX)
/usr/bin/env -i PATH="$PATH" LANG=C LC_ALL=C \
  /usr/bin/python3 -I -m venv "$BUILD_DIRECTORY"
/usr/bin/env -i PATH="$PATH" LANG=C LC_ALL=C PIP_CONFIG_FILE=/dev/null \
  PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
  "$BUILD_DIRECTORY/bin/python" -I -m pip install --no-cache-dir --no-deps \
  --force-reinstall "$SOURCE_DIRECTORY"
/usr/bin/chown -R root:root "$BUILD_DIRECTORY"
/usr/bin/chmod -R go-w "$BUILD_DIRECTORY"

if [ -e "$RUNTIME_DIRECTORY" ] || [ -L "$RUNTIME_DIRECTORY" ]; then
  if [ -L "$RUNTIME_DIRECTORY" ] || [ ! -d "$RUNTIME_DIRECTORY" ] || \
     [ -n "$(/usr/bin/find "$RUNTIME_DIRECTORY" -maxdepth 0 \
       \( ! -user root -o -perm /022 \) -print -quit)" ]; then
    echo "existing approval runtime is unsafe; refusing to replace it" >&2
    exit 2
  fi
  BACKUP_DIRECTORY=$(/usr/bin/mktemp -d /opt/.continuum-memory-polkit-backup.XXXXXX)
  /usr/bin/rmdir -- "$BACKUP_DIRECTORY"
  /usr/bin/mv -- "$RUNTIME_DIRECTORY" "$BACKUP_DIRECTORY"
fi
if ! /usr/bin/mv -- "$BUILD_DIRECTORY" "$RUNTIME_DIRECTORY"; then
  echo "could not activate the staged approval runtime" >&2
  exit 2
fi
BUILD_DIRECTORY=
case "$BACKUP_DIRECTORY" in
  /opt/.continuum-memory-polkit-backup.*)
    /usr/bin/rm -rf -- "$BACKUP_DIRECTORY"
    BACKUP_DIRECTORY=
    ;;
esac

/usr/bin/install -d -o root -g root -m 0755 "$HELPER_DIRECTORY"
/usr/bin/install -o root -g root -m 0755 "$SCRIPT_DIRECTORY/approval-helper" \
  "$HELPER_DIRECTORY/approval-helper"
/usr/bin/install -o root -g root -m 0644 "$SCRIPT_DIRECTORY/org.continuummemory.approval.policy" \
  "$POLICY_DIRECTORY/org.continuummemory.approval.policy"

echo "Installed the Continuum Memory polkit helper."
echo "Start memoryd, then run: continuum approval provision-linux"
