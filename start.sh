#!/bin/bash

set -eu -o pipefail

export DOCKER_BUILDKIT=1

docker pull ubuntu:latest
docker build -t dockerctf --build-arg BUILDKIT_INLINE_CACHE=1 .
docker run -P --rm -it -v $(pwd):/volume dockerctf:latest

