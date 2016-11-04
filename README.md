# QRL
quantum resistant ledger 


Python-based blockchain ledger utilising hash-based one-time merkle tree signature scheme instead of ECDSA.

Hashbased signatures means larger transactions (5kb per tx), longer keypair generation times and the need to record 'state' of transactions as each keypair can only be used once safely. Merkle tree usage enables a single address to be used for signing numerous transactions (up to 256 computationally easily enough). Transactions have an incremented nonce to allow wallets to know which MSS keypair to use - currently Lamport-Diffie and Winternitz one-time signatures as part of merkle signature schemes are natively supported. 






todo:

cleanup:
-tidy up parse function to shorten it and call functions..
-alter the startup to seek the genesis block from the network rather than create locally..

chain:
-disable public key reuse completely.

new:
-enable POW threading when chain synchronised after new block discovery and addition to chain..

node behaviour:
-improve node behaviour to track longest chain from multiple nodes through headerhashes
-alter MB call to also deliver the last 10 (if available) header hashes to allow chain content and height to be verified.. confirmation..
-change node behaviour regarding chains and block addition, rather than just adding the next cryptographically/pow sure block make sure other versions of chain at same level do not exist (orphan chains) : if differing versions of the chain exist on the network then we have to track those changes via a persistent factory list. The node will follow the longest chain but must track divergences until longest chain is sure..will need data structure for this.. 
-other option is to force nodes to follow the longest chain and allow rewriting of last few blocks when a fork happens to switch over to longest chain of POW.
