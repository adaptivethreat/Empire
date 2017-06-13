#!/bin/sh

docker build -t empire -f ./Dockerfile ..
docker run -it empire
