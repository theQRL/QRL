import merkle
import json

num_accounts = 100
file_name = "aws_wallet"

wallets = {}
for i in range(num_accounts):
    print "Generating (",i+1,"/",num_accounts,")"
    wallet = merkle.XMSS(signatures=4096, SEED=None)
    wallets[wallet.address] = wallet.mnemonic

f = open(file_name, 'w')
with open(file_name, 'w') as f:
    json.dump(wallets, f)#, encoding = "ISO-8859-1")

