#!/bin/bash

set -eu -o pipefail

docker pull ubuntu:latest
docker build -t dockerctf .
docker run --rm -it -v $(pwd):/volume dockerctf:latest
