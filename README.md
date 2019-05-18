
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/theQRL/qrllib/master/LICENSE)
[![PyPI version](https://badge.fury.io/py/qrl.svg)](https://badge.fury.io/py/qrl)
[![CircleCI](https://circleci.com/gh/theQRL/QRL.svg?style=shield)](https://circleci.com/gh/theQRL/QRL)
[![CircleCI](https://img.shields.io/circleci/project/github/theQRL/integration_tests/master.svg?label=integration)](https://circleci.com/gh/theQRL/integration_tests)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/e3070763b579456380822b2909259070)](https://www.codacy.com/app/qrl/QRL?utm_source=github.com&utm_medium=referral&utm_content=theQRL/QRL&utm_campaign=Badge_Coverage) 
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e3070763b579456380822b2909259070)](https://www.codacy.com/app/qrl/QRL?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=theQRL/QRL&amp;utm_campaign=Badge_Grade)
[![codebeat badge](https://codebeat.co/badges/9a0c8cad-bfa0-4ea7-89bf-bcb80859ce43)](https://codebeat.co/projects/github-com-theqrl-qrl-master)
[![Snyk Vulnerability Analysis](https://snyk.io/test/github/theQRL/QRL/badge.svg)](https://snyk.io/test/github/theQRL/QRL)


# QRL - Quantum Resistant Ledger 

> Python-based blockchain ledger utilizing hash-based one-time merkle tree signature scheme (XMSS) instead of ECDSA. Proof-of-work block selection via the cryptonight algorithm. Future transition to POS with signed iterative hash chain reveal scheme which is both probabilistic and random (https://github.com/theQRL/pos).
>
> Hash-based signatures means larger transactions (3kb per tx, binary), longer keypair generation times and the need to record 'state' of transactions as each keypair can only be used once safely. Merkle tree usage enables a single address to be used for signing numerous transactions (up to 2^13 computationally easily enough). Currently XMSS/W-OTS+ are natively supported with extensible support for further cryptographic schemes inbuilt. 

# Documentation

We recommend exploring our [Documentation](https://docs.theqrl.org/) 

For instructions on how to install a node, please refer to [Install Node](https://docs.theqrl.org/node/QRLnode/) 

API documentation can be found at [api.theqrl.org](https://api.theqrl.org)

# More information

 * [theqrl.org](https://theqrl.org)
 * [Blog (Medium)](https://medium.com/the-quantum-resistant-ledger)
 * [Original Whitepaper (English)](https://github.com/theQRL/Whitepaper/blob/master/QRL_whitepaper.pdf) or [other languages](https://github.com/theQRL/Whitepaper/blob/master) [These documents are subject to change]
 * [Original Proof of Stake document](https://github.com/theQRL/pos) [This document is subject to change]
 * [Discord Chat](https://discord.gg/RcR9WzX)
 
* * *
