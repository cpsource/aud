#!/bin/bash
# Verify a file with a public key using OpenSSL
# Decode the signature from Base64 format
#
# Usage: verify <file> <signature> <public_key>
#
# NOTE: to generate a public/private key use the following commands:
#
# openssl genrsa -aes128 -passout pass:<passphrase> -out private.pem 2048
# openssl rsa -in private.pem -passin pass:<passphrase> -pubout -out public.pem
#
# where <passphrase> is the passphrase to be used.

filename=$1
publickey=key.pub
signature=verify-source/$filename.signature.sha256

if [[ $# -lt 1 ]] ; then
  echo "Usage: verify <file>"
  exit 1
fi

if [[ ! -d "$1" ]] ; then
	echo -n $1 " "
	openssl base64 -d -in $signature -out /tmp/$filename.sha256
	openssl dgst -sha256 -verify $publickey -signature /tmp/$filename.sha256 $filename
	rm /tmp/$filename.sha256
fi
