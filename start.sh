#!/bin/bash

set -eu -o pipefail

export DOCKER_BUILDKIT=1

docker pull ubuntu:latest
docker build -t dockerctf:latest --build-arg BUILDKIT_INLINE_CACHE=1 .
# NET-ADMIN is needed for vpn connections to work from inside the container
# also add DISPLAY env var and mount X11 socket to support gui apps inside the container
docker run -P --cap-add=NET_ADMIN --rm -it -v $(pwd):/volume -e DISPLAY=${DISPLAY} -v /tmp/.X11-unix:/tmp/.X11-unix dockerctf:latest
