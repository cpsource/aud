#!/bin/bash
# Sign a file with a private key using OpenSSL
# Encode the signature in Base64 format
#
# Usage: sign <file> <private_key>
#
# NOTE: to generate a public/private key use the following commands:
#
# openssl genrsa -aes128 -passout pass:<passphrase> -out private.pem 2048
# openssl rsa -in private.pem -passin pass:<passphrase> -pubout -out public.pem
#
# where <passphrase> is the passphrase to be used.
#
# https://gist.github.com/ezimuel
#
# https://www.zimuel.it/blog/sign-and-verify-a-file-using-openssl
#
# see also verify.sh
#
# more on signatures: https://stackoverflow.com/questions/5140425/openssl-command-line-to-verify-the-signature
#
filename=$1
privatekey=$2

if [[ $# -lt 2 ]] ; then
  echo "Usage: sign <file> <private_key>"
  exit 1
fi

if [[ ! -d "$1" ]] ; then
    openssl dgst -sha256 -sign $privatekey -out /tmp/$filename.sha256 $filename
    openssl base64 -in /tmp/$filename.sha256 -out verify-source/$filename.signature.sha256
    rm /tmp/$filename.sha256
fi
