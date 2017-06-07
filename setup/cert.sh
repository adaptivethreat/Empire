#!/usr/bin/env bash

# generate a self-signed CERT
#openssl genrsa -des3 -out ./data/empire.orig.key 2048
#openssl rsa -in ./data/empire.orig.key -out ./data/empire.key
#openssl req -new -key ./data/empire.key -out ./data/empire.csr
#openssl x509 -req -days 365 -in ./data/empire.csr -signkey ./data/empire.key -out ./data/empire.crt

#openssl req -new -x509 -keyout ../data/empire.pem -out ../data/empire.pem -days 365 -nodes
openssl req -new -x509 -keyout ../data/empire.pem -out ../data/empire.pem -days 365 -nodes -subj "/C=US" >/dev/null 2>&1

echo -e "\n\n [*] Certificate written to ../data/empire.pem\n"
