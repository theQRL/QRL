[![PyPI version](https://badge.fury.io/py/qrl.svg)](https://badge.fury.io/py/qrl)
[![Build Status](https://travis-ci.org/theQRL/QRL.svg?branch=master)](https://travis-ci.org/theQRL/QRL)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/37ffe8d11be94eb5aeb5d29379dd3543)](https://www.codacy.com/app/jleni/QRL?utm_source=github.com&utm_medium=referral&utm_content=theQRL/QRL&utm_campaign=badger)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/37ffe8d11be94eb5aeb5d29379dd3543)](https://www.codacy.com/app/jleni/QRL?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=theQRL/QRL&amp;utm_campaign=Badge_Coverage)
[![Snyk Vulnerability Analysis](https://snyk.io/test/github/theQRL/QRL/badge.svg)](https://snyk.io/test/github/theQRL/QRL)

# QRL - Quantum Resistant Ledger 

> Python-based blockchain ledger utilising hash-based one-time merkle tree signature scheme (XMSS) instead of ECDSA. Proof-of-stake block selection via a signed iterative hash chain reveal scheme which is both probabilistic and random (https://github.com/theQRL/pos).
>
> Hash-based signatures means larger transactions (6kb per tx, binary), longer keypair generation times and the need to record 'state' of transactions as each keypair can only be used once safely. Merkle tree usage enables a single address to be used for signing numerous transactions (up to 2^13 computationally easily enough). Transactions have an incremented nonce to allow wallets to know which MSS keypair to use - currently XMSS/W-OTS+ are natively supported.

More information:
 - [theqrl.org](https://theqrl.org)
 - [Blog (Medium)](https://medium.com/the-quantum-resistant-ledger)
 - [Original Whitepaper (English)](https://github.com/theQRL/Whitepaper/blob/master/QRL_whitepaper.pdf) or [other languages](https://github.com/theQRL/Whitepaper/blob/master) [These documents are subject to change]
 - [Original Proof of Stake document](https://github.com/theQRL/pos) [This document is subject to change]
 

----------------------


# QRL Testnet (Instructions for alpha testers)

*You are welcome to install the alpha version and join the testnet. Be aware that work is in progress and there might be frequent breaking changes.*

## Ubuntu :white_check_mark:

Ensure your apt sources are up to date and install dependencies

```bash
sudo apt update
sudo apt -y install swig3.0 python3-dev python3-pip build-essential cmake pkg-config libssl-dev libffi-dev
```

To get the source and start the node, use the following:

```bash
pip3 install -U qrl
start_qrl
```

## Debian Jessie :white_check_mark:

Debian has some issues in old packages, so you need to install some backports.
Debian does not have `sudo` by default, if you have not installed `sudo`, the use `su` and later do not forget to `exit`.
Do NOT run the node as root.
The following lines show `[sudo]` as optional. Adjust accordingly. 

```bash
echo "deb http://ftp.debian.org/debian jessie-backports main" | [sudo] tee -a /etc/apt/sources.list
[sudo] apt-get update
[sudo] apt-get -t jessie-backports install cmake swig3.0
[sudo] apt-get -y install swig3.0 python3-dev python3-pip build-essential cmake pkg-config libssl-dev libffi-dev
[sudo] pip3 install -U setuptools pip
```

To get the source and start the node, use the following:

```bash
pip3 install -U qrl
start_qrl
```

## OSX :white_check_mark:
If you dont have brew yet, we think you should :) Install brew following the instructions here: [https://brew.sh/](https://brew.sh/)

Now install some dependencies

```bash
brew update
brew install cmake python3 swig boost
```

To get the source and start the node, use the following:

```bash
pip3 install -U qrl
start_qrl
```

## Raspberry Pi (Raspbian Stretch) :white_check_mark:

Install dependencies
```bash
sudo apt update
sudo apt -y install swig3.0 python3-dev build-essential cmake ninja-build libboost-random-dev libssl-dev libffi-dev
sudo pip3 install -U setuptools pip
```

To get the source and start the node, use the following:

```bash
pip3 install -U qrl
start_qrl
```

## Raspberry Pi (Raspbian Jessie) :seedling:
**NOT TESTED. Your feedback is appreciated!**

Debian has some issues in old packages, so you need to install some backports.
Debian does not have `sudo` by default, if you have not installed `sudo`, the use `su` and later do not forget to `exit`.
Do NOT run the node as root.
The following lines show `[sudo]` as optional. Adjust accordingly. 

```bash
echo "deb http://ftp.debian.org/debian jessie-backports main" | [sudo] tee -a /etc/apt/sources.list
[sudo] apt-get update
[sudo] apt-get -t jessie-backports install cmake swig3.0
[sudo] apt-get -y install swig3.0 python3-dev python3-pip build-essential pkg-config libssl-dev libffi-dev
[sudo] pip3 install -U setuptools pip
```

To get the source and start the node, use the following:

```bash
pip3 install -U qrl
start_qrl
```

If you get the following error:

```dependencies not satisfied, run [pip3 install -r requirements.txt] first.
 The 'cffi>=1.7' distribution was not found and is required by cryptography
 get an error with 
``` 

Add the cffi package:

```
[sudo] pip3 install cffi
```

## Windows :seedling:

*Windows support in the current version is limited. An alternative is to use an Ubuntu VM (virtualbox). Docker containers are not working wel in Windows at the moment*

*We are working on a solution to native Windows support*
