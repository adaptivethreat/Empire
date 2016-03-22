#!/bin/bash

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
	cd ./setup
fi

# reset the database
rm ~/.powershell-empire/empire.db
./setup_database.py
cd ..

# remove the debug file if it exists
rm empire.debug

# remove the download folders
rm -rf ./downloads/

# start up Empire
./empire
