#!/bin/bash

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
    cd ./setup
fi

version=$( lsb_release -r | grep -oP "[0-9]+" | head -1 )
if lsb_release -d | grep -q "Fedora"; then
	Release=Fedora
	dnf install -y python-devel m2crypto python-m2ext swig python-iptools python3-iptools libssl-dev
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install pyOpenSSL
elif lsb_release -d | grep -q "Kali"; then
	Release=Kali
	apt-get install -y python-dev python-m2crypto swig python-pip libssl-dev
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install pyOpenSSL
elif lsb_release -d | grep -q "Arch"; then
	Release=Arch
	pacman -S --noconfirm --needed base-devel python2 python2-m2crypto swig python2-pip openssl python2-flask python2-pyopenssl python2-crypto
	pip2 install iptools
	pip2 install pydispatcher
elif lsb_release -d | grep -q "Ubuntu"; then
	Release=Ubuntu
	apt-get install -y python-dev python-m2crypto swig python-pip libssl-dev
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install pyOpenSSL
elif [ -f /usr/bin/apt-get ]; then
	echo "Looks like a Debian/Ubuntu variant. Trying apt-get..."
 	apt-get install -y python-dev python-m2crypto swig python-pip libssl-dev
 	pip install pycrypto
 	pip install iptools
 	pip install pydispatcher
 	pip install flask
 	pip install pyOpenSSL
else
	echo "Unknown distro - install cannot proceed..."
	exit 1;
fi

# set up the database schema
if $Release == "Arch"; then
	python2 ./setup_database.py
else
	./setup_database.py
fi

# generate a cert
./cert.sh

cd ..

echo -e '\n [*] Setup complete!\n'
