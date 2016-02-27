#!/bin/bash

# generate a self-signed CERT
#openssl genrsa -des3 -out~/.powershell-empire/empire.orig.key 2048
#openssl rsa -in~/.powershell-empire/empire.orig.key -out~/.powershell-empire/empire.key
#openssl req -new -key~/.powershell-empire/empire.key -out~/.powershell-empire/empire.csr
#openssl x509 -req -days 365 -in~/.powershell-empire/empire.csr -signkey~/.powershell-empire/empire.key -out~/.powershell-empire/empire.crt

#openssl req -new -x509 -keyout ~/.powershell-empire/empire.pem -out ~/.powershell-empire/empire.pem -days 365 -nodes
openssl req -new -x509 -keyout ~/.powershell-empire/empire.pem -out ~/.powershell-empire/empire.pem -days 365 -nodes -subj "/C=US" >/dev/null 2>&1

echo -e "\n\n [*] Certificate written to ~/.powershell-empire/empire.pem\n"
