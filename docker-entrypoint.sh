#!/usr/bin/env bash

set -Eeuo pipefail

# VPN preparation
mkdir -p /dev/net && \
  mknod /dev/net/tun c 10 200 && \
  chmod 600 /dev/net/tun

exec /bin/tmux
