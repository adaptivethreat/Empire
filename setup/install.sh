#!/bin/bash

# Detecting distro

#Arch Linux
if [ -e /etc/pacman.d ]
then
	# dependencies
	sudo pacman -S swig python2-pip python2-m2crypto python2-crypto python2-iptools

	sudo pip2 install pydispatcher 

	# replacing strings in reset.sh to use python2
	sed -i 's/.\/setup_database.py/python2 setup_database.py/g' reset.sh
	sed -i 's/.\/empire/empire/g' reset.sh

	#Configure database
	python2 setup_database.py

#Debian-like
elif [ -e /etc/apt ]
then
	# dependencies
	sudo apt-get install python-pip python-dev python-m2crypto swig

	pip install pycrypto iptools pydispatcher
	
	#Configure database
	./setup_database.py
fi

sudo mv ../../Empire ../../empire
sudo mv ../../empire /usr/share

# creating a symlink
sudo sh -c "echo \#\!/bin/bash >> /usr/bin/empire"
sudo sh -c "echo cd /usr/share/empire >> /usr/bin/empire"
sudo sh -c "echo exec python2 empire \$\@\ >> /usr/bin/empire"

sudo chmod +x /usr/bin/empire
