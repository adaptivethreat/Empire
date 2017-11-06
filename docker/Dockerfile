# docker build -t empire . 
# docker run -it --net host empire

FROM ubuntu:zesty

WORKDIR /opt/empire

VOLUME /opt/empire/downloads

# add setup files first for layer cache
ADD ./setup /opt/empire/setup

# allow db/cert to be created
RUN mkdir /opt/empire/data

RUN apt-get update && apt-get -y install lsb-release python-pip libssl-dev libxml2-dev libffi-dev git
RUN pip install --upgrade pip

RUN bash ./setup/install.sh

# add remaining files
ADD . /opt/empire/

CMD ./empire
