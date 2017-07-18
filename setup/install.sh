#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo " [!]This script must be run as root" 1>&2
   exit 1
fi

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
    cd ./setup
fi

version=$( lsb_release -r | grep -oP "[0-9]+" | head -1 )
if lsb_release -d | grep -q "Fedora"; then
	Release=Fedora
	dnf install -y make g++ python-devel m2crypto python-m2ext swig python-iptools python3-iptools libxml2-devel default-jdk openssl-devel libssl-dev
	pip install gevent-websocket
	pip install gevent
	pip install setuptools
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install macholib
	pip install dropbox
	pip install pyOpenSSL
	pip install pyinstaller
	pip install zlib_wrapper
	pip install netifaces
elif lsb_release -d | grep -q "Kali"; then
	Release=Kali
	apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libssl-dev
	pip install gevent-websocket
	pip install gevent
	pip install setuptools
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install macholib
	pip install dropbox
	pip install pyOpenSSL
	pip install pyinstaller
	pip install zlib_wrapper
	pip install netifaces
elif lsb_release -d | grep -q "Ubuntu"; then
	Release=Ubuntu
	apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libssl-dev
	pip install gevent
	pip install gevent-websocket
	pip install setuptools
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install pyOpenSSL
	pip install macholib
	pip install dropbox
	pip install pyopenssl
	pip install pyinstaller
	pip install zlib_wrapper
	pip install netifaces
else
	echo "Unknown distro - Debian/Ubuntu Fallback"
	 apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libffi-dev libssl-dev
	 pip install gevent-websocket
	 pip install gevent
	 pip install setuptools
	 pip install pycrypto
	 pip install iptools
	 pip install pydispatcher
	 pip install flask
	 pip install macholib
	 pip install dropbox
	 pip install cryptography
	 pip install pyOpenSSL
	 pip install pyinstaller
	 pip install zlib_wrapper
	 pip install netifaces
fi
tar -xvf ../data/misc/xar-1.5.2.tar.gz
(cd xar-1.5.2 && ./configure)
(cd xar-1.5.2 && make)
(cd xar-1.5.2 && make install)
git clone https://github.com/hogliux/bomutils.git
(cd bomutils && make)
(cd bomutils && make install)
chmod 755 bomutils/build/bin/mkbom && cp bomutils/build/bin/mkbom /usr/local/bin/mkbom
# set up the database schema
./setup_database.py

# generate a cert
./cert.sh

cd ..

echo -e '\n [*] Setup complete!\n'
