#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
   echo " [!]This script must be run as root" 1>&2
   exit 1
fi

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
	cd ./setup
fi

# reset the database
if [ -e ../data/empire.db ]
then
	rm ../data/empire.db
fi

./setup_database.py
cd ..

# remove the debug file if it exists
if [ -e empire.debug ]
then
	rm empire.debug
fi

# remove the download folders
if [ -d ./downloads/ ]
then
	rm -rf ./downloads/
fi

# start up Empire
# ./empire --debug 2
./empire
