#!/usr/bin/env bash

set -Eeuo pipefail

# VPN preparation
mkdir -p /dev/net && \
  mknod /dev/net/tun c 10 200 && \
  chmod 600 /dev/net/tun

# -u to enforce UTF-8 even if the lang env vars do not specify utf-8
exec /bin/tmux -u
