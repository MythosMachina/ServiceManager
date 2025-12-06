#!/usr/bin/env bash
set -euo pipefail

ACCESS_GROUP="${ACCESS_GROUP:-svcweb}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root or via sudo."
  exit 1
fi

echo "== Access group: ${ACCESS_GROUP}"
if ! getent group "${ACCESS_GROUP}" >/dev/null; then
  echo "Creating group ${ACCESS_GROUP}"
  groupadd "${ACCESS_GROUP}"
else
  echo "Group ${ACCESS_GROUP} already exists."
fi

while true; do
  read -rp "Add user to ${ACCESS_GROUP} (leave empty to finish): " user
  if [[ -z "${user}" ]]; then
    break
  fi
  if id "${user}" >/dev/null 2>&1; then
    usermod -aG "${ACCESS_GROUP}" "${user}"
    echo "Added ${user} to ${ACCESS_GROUP}"
  else
    read -rp "User ${user} does not exist. Create it? [y/N]: " yn
    case "${yn}" in
      [yY]*)
        adduser --disabled-password --gecos "" "${user}"
        usermod -aG "${ACCESS_GROUP}" "${user}"
        echo "Created and added ${user} to ${ACCESS_GROUP}"
        ;;
      *)
        echo "Skipped ${user}"
        ;;
    esac
  fi
done

echo "== Final group members:"
getent group "${ACCESS_GROUP}"
