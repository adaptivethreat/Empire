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
ENV STAGING_KEY RANDOM
ENV APP_HOME /usr/src/empire

WORKDIR $APP_HOME

COPY data $APP_HOME/data
COPY lib $APP_HOME/lib
COPY plugins $APP_HOME/plugins
COPY setup $APP_HOME/setup
COPY empire $APP_HOME/empire

RUN apt update -qq && apt-get install -qy \
    lsb-release \
		python \
		python-pip \
		sudo \
		wget \
		curl \
		git \
		libcrypto++-dev \
		libz-dev \
		libxml2-dev \
		libssl1.0-dev \
    && cd setup/ && ./install.sh \
    && chmod +x $APP_HOME/empire \
    && apt autoremove -y \
      git \
  		curl \
  		wget \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["./empire"]
