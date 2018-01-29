#!/usr/bin/env bash
set -ex
# Requires the following packages: git, hub, docker
# SET THE FOLLOWING VARIABLES
USERNAME=empireproject
IMAGE=empire
VERSION="$(cat VERSION)"

# UPDATE THE SOURCE CODE
git pull

# bump version
read -p "[!] Do you want to BUMP the version? [Y/N] " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    # TODO: CHECK IF WE WANT TO BUMP PATCH or MINOR or MAJOR
    docker run --rm -v "$PWD":/app treeder/bump minor
fi
VERSION=`cat VERSION`
echo "[*] Current version: $VERSION"

# TAF, PULL, MERGE DEV
read -p "[!] Do you want to create a new Github Release? [Y/N] " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    git checkout -b "Version-$VERSION"
    git add --all
    git commit -m "Empire $VERSION Release"
    # NO NEED TO TAG IF WE RELEASE
    # git tag -a "$VERSION" -m "Empire $VERSION Release"
    git push origin "Version-$VERSION"
    # git push origin "dev" --tags
    git checkout master
    git merge "Version-$VERSION"
    git push
    hub release create $VERSION -m  "Empire $VERSION Release"
fi


read -p "[!] Do you want to BUILD Docker image? [Y/N] " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    # ALERT VERSION
    echo "[*] Building Version: $VERSION"
    # START BUILD
    ./.build.sh
fi

# DOCKER TAG/VERSIONING
docker tag $USERNAME/$IMAGE:latest $USERNAME/$IMAGE:$VERSION

read -p "[!] Do you want to PUSH to Docker Hub? [Y/N] " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do dangerous stuff
    # PUSH TO DOCKER HUB
    docker push $USERNAME/$IMAGE:latest
    echo "Docker image pushed: $USERNAME/$IMAGE:latest"
    docker push $USERNAME/$IMAGE:$VERSION
    echo "Docker image pushed: $USERNAME/$IMAGE:$VERSION"
fi
