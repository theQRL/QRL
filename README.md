# QRL
quantum resistant ledger 


Python-based blockchain ledger utilising hash-based one-time merkle tree signature scheme instead of ECDSA.

Hashbased signatures means larger transactions (5kb per tx), longer keypair generation times and the need to record 'state' of transactions as each keypair can only be used once safely. Merkle tree usage enables a single address to be used for signing numerous transactions (up to 256 computationally easily enough). Transactions have an incremented nonce to allow wallets to know which MSS keypair to use - currently Lamport-Diffie and Winternitz one-time signatures as part of merkle signature schemes are natively supported. 





