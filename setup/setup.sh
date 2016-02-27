#!/bin/bash

pushd "$(dirname "$0")"

# Setup database schema
./setup_database.py

# Generate a cert
./cert.sh

popd

echo -e '\n [*] Setup complete!\n'
