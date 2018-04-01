#!/bin/bash


# functions

# Install Powershell on Linux
function install_powershell() {
	if uname | grep -q "Darwin"; then
		brew install openssl
		brew install curl --with-openssl
		brew tap caskroom/cask
		brew cask install powershell
	else
		# Deb 9.x
		if cat /etc/debian_version | grep 9.* ; then
			# Install system components
			sudo apt-get update
			sudo apt-get install -y apt-transport-https curl
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Product feed
			sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		fi
		# Deb 8.x
		if cat /etc/debian_version | grep 8.* ; then
			# Install system components
			sudo apt-get update
			sudo apt-get install -y apt-transport-https curl gnupg
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Product feed
			sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main" > /etc/apt/sources.list.d/microsoft.list'
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		fi
		#Ubuntu 14.x
		if cat /etc/lsb-release | grep 'DISTRIB_RELEASE=14'; then
			# Install system components
			sudo apt-get update
			sudo apt-get install -y apt-transport-https curl 
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Ubuntu repository
			curl https://packages.microsoft.com/config/ubuntu/14.04/prod.list | sudo tee /etc/apt/sources.list.d/microsoft.list
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		fi
		#Ubuntu 16.x
		if cat /etc/lsb-release | grep 'DISTRIB_RELEASE=16'; then
			# Install system components
			sudo apt-get update
			sudo apt-get install -y apt-transport-https curl 
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Ubuntu repository
			curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list | sudo tee /etc/apt/sources.list.d/microsoft.list
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		fi
		#Ubuntu 17.x
		if  cat /etc/lsb-release | grep 'DISTRIB_RELEASE=17'; then
			# Install system components
			sudo apt-get update
			sudo apt-get install -y apt-transport-https curl 
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Ubuntu repository
			curl https://packages.microsoft.com/config/ubuntu/17.04/prod.list | sudo tee /etc/apt/sources.list.d/microsoft.list
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		fi
		#Kali Linux
		if cat /etc/lsb-release | grep -i 'Kali'; then
			# Install prerequisites
			apt-get update
			apt-get install -y curl gnupg apt-transport-https
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Product feed
			sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
			# Update the list of products
			apt-get update
			# Install PowerShell
			apt-get install -y powershell
		fi
	 fi
        if ls /opt/microsoft/powershell/*/DELETE_ME_TO_DISABLE_CONSOLEHOST_TELEMETRY; then
            rm /opt/microsoft/powershell/*/DELETE_ME_TO_DISABLE_CONSOLEHOST_TELEMETRY
        fi
	mkdir -p /usr/local/share/powershell/Modules
	cp -r ../lib/powershell/Invoke-Obfuscation /usr/local/share/powershell/Modules
}


# Ask for the administrator password upfront so sudo is no longer required at Installation.
sudo -v

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
    cd ./setup
fi

# Check for PIP otherwise install it
if ! which pip > /dev/null; then
	wget https://bootstrap.pypa.io/get-pip.py
	python get-pip.py
fi

if uname | grep -q "Darwin"; then
	install_powershell
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
		sudo dnf install -y make g++ python-devel m2crypto python-m2ext swig python-iptools python3-iptools libxml2-devel default-jdk openssl-devel libssl1.0.0 libssl-dev build-essential
		pip install --upgrade pip
		sudo pip install -r requirements.txt 
	elif lsb_release -d | grep -q "Kali"; then
		Release=Kali
		wget http://ftp.us.debian.org/debian/pool/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u7_amd64.deb
		dpkg -i libssl1.0.0_1.0.1t-1+deb8u7_amd64.deb
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk zlib1g-dev libssl1.0-dev build-essential libssl1.0-dev libxml2-dev zlib1g-dev
		pip install --upgrade pip
		sudo pip install -r requirements.txt 
		install_powershell
	elif lsb_release -d | grep -q "Ubuntu"; then
		Release=Ubuntu
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libssl1.0.0 libssl-dev build-essential
		pip install --upgrade pip
		sudo pip install -r requirements.txt 
		install_powershell
	else
		echo "Unknown distro - Debian/Ubuntu Fallback"
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libffi-dev libssl1.0.0 libssl-dev build-essential
		pip install --upgrade pip
		sudo pip install -r requirements.txt 
		install_powershell
	fi
fi

# Installing xar
tar -xvf ../data/misc/xar-1.5.2.tar.gz
(cd xar-1.5.2 && ./configure)
(cd xar-1.5.2 && make)
(cd xar-1.5.2 && sudo make install)

#Installing bomutils
git clone https://github.com/hogliux/bomutils.git
(cd bomutils && make)
(cd bomutils && make install)

# NIT: This fails on OSX. Leaving it only on Linux instances. 
if uname | grep -q "Linux"; then
	(cd bomutils && make install)
fi
chmod 755 bomutils/build/bin/mkbom && sudo cp bomutils/build/bin/mkbom /usr/local/bin/.

# set up the database schema
python ./setup_database.py

# generate a cert
./cert.sh

cd ..

echo -e '\n [*] Setup complete!\n'
