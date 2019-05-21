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
			sudo apt-get install -y apt-transport-https curl
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Product feed
			sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		# Deb 8.x
		elif cat /etc/debian_version | grep 8.* ; then
			# Install system components
			sudo apt-get install -y apt-transport-https curl gnupg
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Product feed
			sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main" > /etc/apt/sources.list.d/microsoft.list'
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		#Ubuntu
        elif lsb_release -d | grep -q "Ubuntu"; then
			# Read Ubuntu version
			local ubuntu_version=$( grep 'DISTRIB_RELEASE=' /etc/lsb-release | grep -o -E [[:digit:]]+\\.[[:digit:]]+ )
			# Install system components
			sudo apt-get install -y apt-transport-https curl
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Ubuntu repository
			curl https://packages.microsoft.com/config/ubuntu/$ubuntu_version/prod.list | sudo tee /etc/apt/sources.list.d/microsoft.list
			# Update the list of products
			sudo apt-get update
			# Install PowerShell
			sudo apt-get install -y powershell
		#Kali Linux
		elif cat /etc/lsb-release | grep -i 'Kali'; then
			# Install prerequisites
			apt-get install -y curl gnupg apt-transport-https
			# Import the public repository GPG keys
			curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
			# Register the Microsoft Product feed
			sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
			# Update the list of products
			apt-get update
                        # Install libucu57 as stated in https://web.archive.org/web/20190501222044/https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-6#installation---kali
                        wget http://http.us.debian.org/debian/pool/main/i/icu/libicu57_57.1-6+deb9u2_amd64.deb
                        if sha256sum libicu57_57.1-6+deb9u2_amd64.deb | grep '^c2dee82e7ae8fa4dc8fd0d9ad5a28cd41598cfccf5d0a71d0cd6a6bb4ac71f25' >/dev/null; then
                          dpkg -i libicu57_57.1-6+deb9u2_amd64.deb
                        else
                          echo "Failed to install libicu57"
                          exit 1
                        fi
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

if uname | grep -q "Darwin"; then
    Xar_version="xar-1.5.2"
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
        Xar_version="xar-1.5.2"
		sudo dnf install -y make automake gcc gcc-c++  python-devel m2crypto python-m2ext swig libxml2-devel java-openjdk-headless openssl-devel openssl libffi-devel redhat-rpm-config
		sudo pip install -r requirements.txt
	elif lsb_release -d | grep -q "Kali"; then
		Release=Kali
        Xar_version="xar-1.6.1"
		apt-get update
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk zlib1g-dev libssl1.1 build-essential libssl-dev libxml2-dev zlib1g-dev
		sudo pip install -r requirements.txt
		install_powershell
	elif lsb_release -d | grep -q "Ubuntu"; then
		Release=Ubuntu
		sudo apt-get update
        if [ $(lsb_release -rs | cut -d "." -f 1) -ge 18 ]; then
            LibSSL_pkgs="libssl1.1 libssl-dev"
            Pip_file="requirements.txt"
            Xar_version="xar-1.6.1"
        else
            LibSSL_pkgs="libssl1.0.0 libssl-dev"
            Pip_file="requirements_libssl1.0.txt"
            Xar_version="xar-1.5.2"
        fi
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk $LibSSL_pkgs build-essential
		sudo pip install -r $Pip_file
		install_powershell
	else
		echo "Unknown distro - Debian/Ubuntu Fallback"
		sudo apt-get update
        if [ $(cut -d "." -f 1 /etc/debian_version) -ge 9 ]; then
            LibSSL_pkgs="libssl1.1 libssl-dev"
            Pip_file="requirements.txt"
            Xar_version="xar-1.6.1"
        else
            LibSSL_pkgs="libssl1.0.0 libssl-dev"
            Pip_file="requirements_libssl1.0.txt"
            Xar_version="xar-1.5.2"
        fi
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libffi-dev $LibSSL_pkgs build-essential
		sudo pip install -r $Pip_file
		install_powershell
	fi
fi

# Installing xar
tar -xvf ../data/misc/$Xar_version.tar.gz
(cd $Xar_version && ./configure)
(cd $Xar_version && make)
(cd $Xar_version && sudo make install)

#Installing bomutils
git clone https://github.com/hogliux/bomutils.git
(cd bomutils && make)
(cd bomutils && sudo make install)

# NIT: This fails on OSX. Leaving it only on Linux instances.
if uname | grep -q "Linux"; then
	(cd bomutils && sudo make install)
fi
chmod 755 bomutils/build/bin/mkbom && sudo cp bomutils/build/bin/mkbom /usr/local/bin/.

# set up the database schema
python ./setup_database.py

# generate a cert
./cert.sh

cd ..

echo -e '\n [*] Setup complete!\n'
