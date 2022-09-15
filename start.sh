#!/bin/bash

set -eu -o pipefail

export DOCKER_BUILDKIT=1

docker pull ubuntu:latest
docker build -t dockerctf:latest --build-arg BUILDKIT_INLINE_CACHE=1 .
docker run -P --cap-add=NET_ADMIN --rm -it -v $(pwd):/volume dockerctf:latest

