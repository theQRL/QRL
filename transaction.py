from StringIO import StringIO
import simplejson as json
import configuration as c
import merkle
from merkle import sha256
import helper
import json

# A base class to be inherited by all other transaction
class Transaction(object):
    def __init__(self):
        pass

    def process_XMSS(self, type, txfrom, txhash, data):
        self.txfrom = txfrom.encode('ascii')
        self.txhash = txhash
        # data = self.my[0][1]
        S = data.SIGN(str(self.txhash))  # Sig = {i, s, auth_route, i_bms, self.pk(i), self.PK_short}
        self.i = S[0]
        self.signature = S[1]
        self.merkle_path = S[2]
        self.i_bms = S[3]
        self.pub = S[4]
        self.PK = S[5]
        self.type = type

    def dict_to_transaction(self, dict_tx):
        self.txfrom = dict_tx['txfrom'].encode('ascii')
        self.txhash = self.reformat(dict_tx['txhash'])
        self.i = int(dict_tx['i'])
        self.signature = self.reformat(dict_tx['signature'])
        self.merkle_path = self.reformat(dict_tx['merkle_path'])
        self.i_bms = self.reformat(dict_tx['i_bms'])
        self.pub = self.reformat(dict_tx['pub'])
        self.PK = self.reformat(dict_tx['PK'])
        self.type = dict_tx['type'].encode('ascii')
        return self

    def json_to_transaction(self, dict_tx):
        return self.dict_to_transaction(json.loads(dict_tx))

    def reformat(self, srcList):
        destList = []
        if isinstance(srcList, list):
            for item in srcList:
                destList.append(self.reformat(item))
            return destList
        elif isinstance(srcList, unicode):
            return srcList.encode('ascii')

        return srcList

    def transaction_to_json(self):
        return json.dumps(self.__dict__)

    def get_message_hash(self):
        message = StringIO()
        '''
        message.write(self.txfrom)
        message.write(self.txhash)
        message.write(self.i)
        message.write(self.signature)
        message.write(self.merkle_path)
        message.write(self.i_bms)
        message.write(self.pub)
        message.write(self.PK)
        message.write(self.type)
        '''
        return message

# classes
class StakeTransaction(Transaction):
    def __init__(self):
        Transaction.__init__(self)

    def get_message_hash(self):
        message = super(StakeTransaction, self).get_message_hash()
        #message.write(self.epoch)
        message.write(self.hash)
        message.write(str(self.first_hash))
        return sha256(message.getvalue())

    def dict_to_transaction(self, dict_tx):
        super(StakeTransaction, self).dict_to_transaction(dict_tx)
        self.epoch = int(dict_tx['epoch'])
        self.balance = dict_tx['balance']
        self.hash = []
        for hash_item in dict_tx['hash']:
            self.hash.append(hash_item.encode('ascii'))
        self.first_hash = dict_tx['first_hash']
        if self.first_hash:
            self.first_hash = self.first_hash.encode('ascii')
        return self

    def create_stake_transaction(self, mining_address, blocknumber, data, hashchain_terminator=None, first_hash=None, balance=None):
        if not balance:
            printL (( 'Invalid Balance', balance ))
            raise Exception
        self.epoch = blocknumber // c.blocks_per_epoch  # in this block the epoch is..
        self.first_hash = first_hash
        self.balance = balance

        if hashchain_terminator is None:
            self.hash = data.hashchain_reveal(epoch=self.epoch + 1)  # my[0][1].hc_terminator
        else:
            self.hash = hashchain_terminator
        self.process_XMSS('ST', mining_address, self.hash, data)  # self.hash to be replaced with self.txhash
        return self

    def validate_tx(self):
        if self.type != 'ST':
            return False
        if self.first_hash:
            if sha256(self.first_hash) != self.hash[-1]:
                printL ((' First_hash doesnt stake to hashterminator '))
                return False

        for i in range(len(self.hash)):
            self.hash[i] = str(self.hash[i])

        if merkle.xmss_verify(str(self.hash),
                              [self.i, self.signature, self.merkle_path, self.i_bms, self.pub, self.PK]) is False:
            return False
        if helper.xmss_checkaddress(self.PK, self.txfrom) is False:
            return False

        return True

    def state_validate_tx(self, state):
        if self.type != 'ST':
            return False
        pub = self.pub
        pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]
        pubhash = sha256(''.join(pub))

        if self.balance > state.state_balance(self.txfrom):
            printL (( 'Stake Transaction Balance is exceeds maximum balance' ))
            printL (( 'Max Balance Expected ', state.state_balance(self.txfrom) ))
            printL (( 'Balance found ', self.balance ))
            return False

        if pubhash in state.state_pubhash(self.txfrom):
            printL(('State validation failed for', self.hash, 'because: OTS Public key re-use detected'))
            return False

        return True


class SimpleTransaction(Transaction):  # creates a transaction python class object which can be jsonpickled and sent into the p2p network..
    def __init__(self):  # nonce removed..
        Transaction.__init__(self)

    def get_message_hash(self):
        message = super(SimpleTransaction, self).get_message_hash()
        #message.write(self.epoch)
        #message.write(self.nonce)
        #message.write(self.txto)
        #message.write(self.amount)
        #message.write(self.fee)
        #message.write(self.ots_key)
        message.write(self.txhash)
        return sha256(message.getvalue())

    def dict_to_transaction(self, dict_tx):
        super(SimpleTransaction, self).dict_to_transaction(dict_tx)
        self.nonce = int(dict_tx['nonce'])
        self.txto = dict_tx['txto'].encode('ascii')
        self.amount = int(dict_tx['amount'])
        self.fee = int(dict_tx['fee'])
        self.ots_key = int(dict_tx['ots_key'])
        self.pubhash = dict_tx['pubhash']
        self.txhash = dict_tx['txhash']
        #for hash_item in dict_tx['hash']:
        #    self.hash.append(hash_item.encode('ascii'))
        return self

    def pre_condition(self, state):
        # if state_uptodate() is False:
        #	printL(( 'Warning state not updated to allow safe tx validation, tx validity could be unreliable..'))
        #	return False

        if state.state_balance(self.txfrom) is 0:
            printL(('State validation failed for', self.txhash, 'because: Empty address'))
            return False

        if state.state_balance(self.txfrom) < self.amount:
            printL(('State validation failed for', self.txhash, 'because: Insufficient funds'))
            return False

        return True

    def create_simple_transaction(self, state, txfrom, txto, amount, data, fee=0, hrs=''):
        self.txfrom = txfrom
        self.nonce = 0
        self.txto = txto
        self.amount = int(amount)
        self.fee = int(fee)
        self.ots_key = data.index

        pub = data.pk()
        pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]
        self.pubhash = sha256(''.join(pub))
        self.txhash = sha256(''.join(self.txfrom + str(self.pubhash) + self.txto + str(self.amount) + str(self.fee)))
        self.merkle_root = data.root
        if not self.pre_condition(state):
            return False

        self.process_XMSS('TX', txfrom, self.txhash, data)

        return self

    def validate_tx(self):
        # cryptographic checks
        if self.txhash != sha256(''.join(self.txfrom + str(self.pubhash)) + self.txto + str(self.amount) + str(
                self.fee)):
            return False

        # SIG is a list composed of: i, s, auth_route, i_bms, pk[i], PK
        if self.type != 'TX':
            return False

        if merkle.xmss_verify(self.txhash,
                              [self.i, self.signature, self.merkle_path, self.i_bms, self.pub, self.PK]) is False:
            return False

        if helper.xmss_checkaddress(self.PK, self.txfrom) is False:
            return False

        return True

    def state_validate_tx(self, state,
                          transaction_pool):  # checks new tx validity based upon node statedb and node mempool.

        if not self.pre_condition(state):
            return False

        pub = self.pub
        if self.type != 'TX':
            return False

        pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]

        pubhash = sha256(''.join(pub))

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue
            pub = txn.pub
            if txn.type != 'TX':
                return False
            pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]

            pubhashn = sha256(''.join(pub))

            if pubhashn == pubhash:
                printL(('State validation failed for', self.txhash, 'because: OTS Public key re-use detected'))
                return False

        if pubhash in state.state_pubhash(self.txfrom):
            printL(('State validation failed for', self.txhash, 'because: OTS Public key re-use detected'))
            return False

        return True
