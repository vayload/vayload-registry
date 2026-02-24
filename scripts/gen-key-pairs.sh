#!/bin/bash
set -e

# Ensure the data directory
mkdir -p data

# Generate private key (Ed25519)
openssl genpkey -algorithm Ed25519 -out data/vg-private.pem

# Extract public key
openssl pkey -in data/vg-private.pem -pubout -out data/vg-public.pem

echo "Keys generated:"
echo " - data/vg-private.pem"
echo " - data/vg-public.pem"

echo "Base64 public key"
echo $(cat data/vg-public.pem | base64 | tr -d '\n')
