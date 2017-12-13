# NOTE: Only use this when you want to build image locally
#       else use `docker pull empireproject\empire:{VERSION}`
#       all image versions can be found at: https://hub.docker.com/r/empireproject/empire/

# BUILD COMMANDS :
# 1) build command: `docker build -t empireproject/empire .`
# 2) create volume storage: `docker create -v /opt/Empire --name data empireproject/empire`
# 3) run out container: `docker run -ti --volumes-from data empireproject/empire /bin/bash`

FROM debian:stretch

LABEL maintainer="EmpireProject"

ENV DEBIAN_FRONTEND noninteractive
ENV EMPIRE_VERSION 2.3
ENV STAGING_KEY RANDOM

RUN apt update -qq && apt-get install -qy \
		apt-transport-https \
    wget \
    lsb-release \
    python2.7 \
    python-pip \
    python-m2crypto \
    sudo \
  && wget -nv https://github.com/EmpireProject/Empire/archive/$EMPIRE_VERSION.tar.gz --output-document /empire.tar.gz \
  && mkdir -p /empire \
  && tar zxf empire.tar.gz -C /empire --strip-components=1 \
  && cd /empire/setup/ && ./install.sh \
  && chmod +x /empire/empire \
  && rm /empire.tar.gz \
  && apt autoremove -y \
    apt-transport-https \
    build-essential \
    git \
    wget \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /empire
ENTRYPOINT ["./empire"]
