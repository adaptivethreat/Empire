#!/usr/bin/env bash
set -ex
# SET THE FOLLOWING VARIABLES
# docker hub username
USERNAME=empireproject
# image name
IMAGE=empire
# version
VERSION="$(curl -s https://raw.githubusercontent.com/EmpireProject/Empire/master/lib/common/empire.py | grep "VERSION =" | cut -d '"' -f2)"

docker build --build-arg empireversion="$VERSION" -t $USERNAME/$IMAGE:latest .
