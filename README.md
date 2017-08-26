[![Codacy Badge](https://api.codacy.com/project/badge/Grade/37ffe8d11be94eb5aeb5d29379dd3543)](https://www.codacy.com/app/jleni/QRL?utm_source=github.com&utm_medium=referral&utm_content=theQRL/QRL&utm_campaign=badger)
[![GitHub version](https://badge.fury.io/gh/theqrl%2Fqrl.svg)](https://badge.fury.io/gh/theqrl%2Fqrl)
[![Build Status](https://travis-ci.org/theQRL/QRL.svg?branch=master)](https://travis-ci.org/theQRL/QRL)
[![Coverage Status](https://coveralls.io/repos/github/theQRL/QRL/badge.svg?branch=master)](https://coveralls.io/github/theQRL/QRL?branch=master)

# QRL
Quantum Resistant Ledger 

[theqrl.org](https://theqrl.org)

Python-based blockchain ledger utilising hash-based one-time merkle tree signature scheme (XMSS) instead of ECDSA. Proof-of-stake block selection via a signed iterative hash chain reveal scheme which is both probabilistic and random (https://github.com/theQRL/pos).

Hash-based signatures means larger transactions (6kb per tx, binary), longer keypair generation times and the need to record 'state' of transactions as each keypair can only be used once safely. Merkle tree usage enables a single address to be used for signing numerous transactions (up to 2^13 computationally easily enough). Transactions have an incremented nonce to allow wallets to know which MSS keypair to use - currently Lamport-Diffie and Winternitz one-time signatures as part of merkle signature schemes and XMSS/W-OTS+ are natively supported.






