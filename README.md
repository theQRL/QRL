# QRL
quantum resistant ledger 


Python-based blockchain ledger utilising hash-based one-time merkle tree signature scheme instead of ECDSA.

At present communication with node is performed via a telnet localhost connection on port 2000. Internet p2p traffic is on port 9000 (in progress). Hashbased signatures means larger transactions (5kb per tx), longer keypair generation times and the need to record 'state' of transactions as each keypair can only be used once. Merkle tree usage enables a single address to be used for signing numerous transactions (up to 256 easily enough). Transactions have an incremented nonce to allow wallets to know which MSS keypair to use.

Todo: implement core p2p message passing for tx and blocks, network chain synchronisation, tx/block validation, implement POW algo. Once the basic node is validating and functional compile it as a standalone app/daemon.

Ideas: use of a pseudorandom algo to generate the OTS private keys for MSS (solex). Optimisation of merkle proof algo should be trivial and is a large part of key generation time presently, limited to ~256 W-OTS keypairs currently.
