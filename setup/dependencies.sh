#!/bin/bash
distro=$(lsb_release -si)

if [[ $EUID -ne 0 ]]; then
  echo "[!] This must be run as root"
  exit 1
fi

if ${distro} ==  "Fedora"; then
	dnf install -y python-devel m2crypto python-m2ext swig python-iptools python3-iptools 
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
elif ${distro} == "Kali"; then
	apt-get install -y python-dev python-m2crypto swig python-pip
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
elif [[ ${distro} == "Ubuntu" ]] || [[ ${distro} == "Debian" ]] ; then
	apt-get install -y python-dev python-m2crypto swig
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
else
	echo "[!] Unsupported distro, please submit a issue at https://github.com/PowerShellEmpire/Empire/issues"
fi
