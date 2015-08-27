#!/bin/bash

apt-get install python-pip

#ubuntu 14.04 LTS dependencies
apt-get install python-dev
apt-get install python-m2crypto
apt-get install swig
pip install pycrypto

#kali dependencies
pip install iptools
pip install pydispatcher

#deploy dependencies

# Install impacket
git clone https://github.com/coresecurity/impacket
cd impacket
python2.7 setup.py install

# Install pyasn1
wget https://pypi.python.org/packages/source/p/pyasn1/pyasn1-0.1.8.tar.gz#md5=7f6526f968986a789b1e5e372f0b7065
tar xvf pyasn1-0.1.8.tar.gz
cd pyasn1-0.1.8
python2.7 setup.py install

./setup_database.py
