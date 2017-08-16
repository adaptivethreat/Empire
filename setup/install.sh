#!/bin/bash

# Ask for the administrator password upfront so sudo is no longer required at Installation. 
sudo -v

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
    cd ./setup
fi

if uname | grep -q "Darwin"; then 
	sudo pip install -r requirements.txt --global-option=build_ext \
		--global-option="-L/usr/local/opt/openssl/lib" \
		--global-option="-I/usr/local/opt/openssl/include"
	# In order to build dependencies these should be exproted. 
	export LDFLAGS=-L/usr/local/opt/openssl/lib
	export CPPFLAGS=-I/usr/local/opt/openssl/include
else
	version=$( lsb_release -r | grep -oP "[0-9]+" | head -1 )
	if lsb_release -d | grep -q "Fedora"; then
		Release=Fedora
		sudo dnf install -y make g++ python-devel m2crypto python-m2ext \
			swig python-iptools python3-iptools libxml2-devel default-jdk openssl-devel libssl-dev
		pip install -r requirements.txt
	elif lsb_release -d | grep -q "Kali"; then
		Release=Kali
		sudo apt-get install -y make g++ python-dev python-m2crypto swig \
			python-pip libxml2-dev default-jdk libssl-dev
		pip install -r requirements.txt
	elif lsb_release -d | grep -q "Ubuntu"; then
		Release=Ubuntu
		sudo apt-get install -y make g++ python-dev python-m2crypto swig \
			python-pip libxml2-dev default-jdk libssl-dev
		pip install -r requirements.txt
	else
		echo "Unknown distro - Debian/Ubuntu Fallback"
		sudo apt-get install -y make g++ python-dev python-m2crypto swig \
			python-pip libxml2-dev default-jdk libffi-dev libssl-dev
		pip install -r requirements.txt
	fi
fi

tar -xvf ../data/misc/xar-1.5.2.tar.gz
(cd xar-1.5.2 && ./configure )
(cd xar-1.5.2 && make)
(cd xar-1.5.2 && sudo make install)
git clone https://github.com/hogliux/bomutils.git
(cd bomutils && make)

# NIT: This fails on OSX. Leaving it only on Linux instances. 
if uname | grep -q "Linux"; then
	(cd bomutils && make install)
fi

chmod 755 bomutils/build/bin/mkbom && sudo cp bomutils/build/bin/mkbom /usr/local/bin/.
# set up the database schema
./setup_database.py

# generate a cert
./cert.sh

cd ..

echo -e '\n [*] Setup complete!\n'
