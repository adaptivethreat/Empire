#!/bin/bash

SCRIPT="$(readlink -f ${BASH_SOURCE[0]})"
DIR="$(dirname $SCRIPT)"
echo $DIR

if getopts ":y" opt; then
    case $opt in
        y)
            apt-get install python-pip -y
            apt-get install python-dev -y
            apt-get install python-m2crypto -y
            apt-get install swig -y
            pip install pycrypto
            pip install iptools
            pip install pydispatcher
	
            $DIR/setup_database.py -y
        ;;
    esac
else

    apt-get install python-pip

    # Ubuntu 14.04 LTS dependencies
    apt-get install python-dev
    apt-get install python-m2crypto
    apt-get install swig
    pip install pycrypto

    # Kali Dependencies
    pip install iptools
    pip install pydispatcher
    
    # Setup Database
    $DIR/setup_database.py

fi
