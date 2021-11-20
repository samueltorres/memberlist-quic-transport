#!/usr/bin/env bash

# generate ca
cfssl gencert -initca ./ca-csr.json | cfssljson -bare ca

# generate cert
cfssl gencert -ca ca.pem -ca-key ca-key.pem cert-csr.json | cfssljson -bare cert