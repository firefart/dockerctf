#!/bin/bash

set -eu -o pipefail

export DOCKER_BUILDKIT=1

docker pull firefart/dockerctf:latest
mkdir -p "$(pwd)/share"
# NET-ADMIN is needed for vpn connections to work from inside the container
# also add DISPLAY env var and mount X11 socket to support gui apps inside the container
docker run -P --cap-add=NET_ADMIN --rm -it -v "$(pwd)/share:/volume"  -v "$(HOME)/.claude:/root/.claude" -e DISPLAY=${DISPLAY} -v /tmp/.X11-unix:/tmp/.X11-unix firefart/dockerctf:latest
