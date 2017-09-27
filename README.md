[![GitHub version](https://badge.fury.io/gh/theqrl%2Fqrl.svg)](https://badge.fury.io/gh/theqrl%2Fqrl)
[![Build Status](https://travis-ci.org/theQRL/QRL.svg?branch=master)](https://travis-ci.org/theQRL/QRL)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/37ffe8d11be94eb5aeb5d29379dd3543)](https://www.codacy.com/app/jleni/QRL?utm_source=github.com&utm_medium=referral&utm_content=theQRL/QRL&utm_campaign=badger)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/37ffe8d11be94eb5aeb5d29379dd3543)](https://www.codacy.com/app/jleni/QRL?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=theQRL/QRL&amp;utm_campaign=Badge_Coverage)
[![Coverage Status](https://coveralls.io/repos/github/theQRL/QRL/badge.svg?branch=master)](https://coveralls.io/github/theQRL/QRL?branch=master)
[![Known Vulnerabilities](https://snyk.io/test/github/theQRL/QRL/badge.svg)](https://snyk.io/test/github/theQRL/QRL)

# QRL - Quantum Resistant Ledger 

> Python-based blockchain ledger utilising hash-based one-time merkle tree signature scheme (XMSS) instead of ECDSA. Proof-of-stake block selection via a signed iterative hash chain reveal scheme which is both probabilistic and random (https://github.com/theQRL/pos).
>
> Hash-based signatures means larger transactions (6kb per tx, binary), longer keypair generation times and the need to record 'state' of transactions as each keypair can only be used once safely. Merkle tree usage enables a single address to be used for signing numerous transactions (up to 2^13 computationally easily enough). Transactions have an incremented nonce to allow wallets to know which MSS keypair to use - currently Lamport-Diffie and Winternitz one-time signatures as part of merkle signature schemes and XMSS/W-OTS+ are natively supported.

More information:
 - [theqrl.org](https://theqrl.org)
 - [Blog (Medium)](https://medium.com/the-quantum-resistant-ledger)
 - [Original Whitepaper (English)](https://github.com/theQRL/Whitepaper/blob/master/QRL_whitepaper.pdf) or [other languages](https://github.com/theQRL/Whitepaper/blob/master) [These documents are subject to change]
 - [Original Proof of Stake document](https://github.com/theQRL/pos) [This document is subject to change]
 

----------------------


# QRL Testnet (Instructions for alpha testers)

*You are welcome to install the alpha version and join the testnet. Be aware that work is in progress and there might be frequent breaking changes.*

## Ubuntu :white_check_mark:

Ensure your apt sources are up to date

`sudo apt update`

Install packages

```
sudo apt -y install swig3.0 python3-dev build-essential cmake pkg-config
```

To get the source and start the node, use the following:

```
git clone https://github.com/theQRL/QRL.git
cd QRL/
sudo pip3 install -r requirements.txt
python3 start_qrl.py
```

## OSX :white_check_mark:
If you dont have brew yet, we think you should :) Install brew following the instructions here: [https://brew.sh/](https://brew.sh/)

Now install some dependencies

```bash
brew install cmake python3 swig
```

To get the source and start the node, use the following:

```
git clone https://github.com/theQRL/QRL.git
cd QRL/
sudo pip3 install -r requirements.txt
python3 start_qrl.py
```

## Raspberry Pi :white_check_mark:

Install dependencies
```
sudo apt -y install swig3.0 python3-dev build-essential cmake ninja-build
sudo pip3 install -U setuptools
```

To get the source and start the node, use the following:

```
git clone https://github.com/theQRL/QRL.git
cd QRL/
sudo pip3 install -r requirements.txt
python3 start_qrl.py
```

## Windows :seedling:

*Windows support in the current version is limited. An alternative is to use a Docker container*

*We are working on a solution to native Windows support*
