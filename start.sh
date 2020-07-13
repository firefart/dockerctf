#!/bin/bash

set -eu -o pipefail

docker pull ubuntu:latest
DOCKER_BUILDKIT=1 docker build -t dockerctf .
docker run -P --rm -it -v $(pwd):/volume dockerctf:latest
