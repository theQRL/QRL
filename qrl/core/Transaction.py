# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from StringIO import StringIO
from abc import ABCMeta

import simplejson as json

import qrl
from qrl.core import logger, helper, config
from qrl.core.Transaction_subtypes import *
from qrl.crypto.hashchain import HashChain
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS


class Transaction(object):
    """
    Abstract Base class to be derived by all other transactions
    """
    __metaclass__ = ABCMeta

    # FIXME: Use metaclass and make this class abstract. Enforce same API in derived classes

    def __init__(self):
        self.nonce = 0  # Nonce is set when block is being created
        self.ots_key = None
        self.pubhash = None
        self.txhash = None
        self.txfrom = None
        self.i = None
        self.signature = None
        self.merkle_path = None
        self.i_bms = None
        self.pub = None
        self.PK = None

    @staticmethod
    def from_txdict(txdict):
        """
        :param txdict:
        :type txdict:
        :return:
        :rtype:
        >>> from qrl.core.doctest_data import *;  isinstance(Transaction.from_txdict(test_txdict_Simple), SimpleTransaction)
        True
        >>> from qrl.core.doctest_data import *;  isinstance(Transaction.from_txdict(test_txdict_Stake), StakeTransaction)
        True
        >>> from qrl.core.doctest_data import *;  isinstance(Transaction.from_txdict(test_txdict_CoinBase), CoinBase )
        True
        >>> from qrl.core.doctest_data import *;  isinstance(Transaction.from_txdict(test_txdict_Lattice), LatticePublicKey)
        True
        """
        # type: (dict) -> Transaction

        # TODO: This would probably make more sense in a factory. Wait for protobuf3
        # FIXME: Avoid dictionary lookups for a small fixed amount of keys
        type_to_txn = {
            TX_SUBTYPE_TX: SimpleTransaction,
            TX_SUBTYPE_STAKE: StakeTransaction,
            TX_SUBTYPE_COINBASE: CoinBase,
            TX_SUBTYPE_LATTICE: LatticePublicKey
        }

        subtype = txdict['subtype'].encode('ascii')
        return type_to_txn[subtype]()._dict_to_transaction(txdict)

    @staticmethod
    def generate_pubhash(pub):
        pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]
        return sha256(''.join(pub))

    @staticmethod
    def nonce_allocator(self, tx_list, block_chain_buffer, blocknumber=-1):
        if blocknumber == -1:
            blocknumber = block_chain_buffer.height()

        addr_state = {}
        for tx in tx_list:
            if tx.txfrom not in addr_state:
                addr_state[tx.txfrom] = block_chain_buffer.get_stxn_state(blocknumber, tx.txfrom)

            addr_state[tx.txfrom][0] += 1
            tx.nonce = addr_state[tx.txfrom][0]

        return tx_list

    def _process_XMSS(self, txfrom, txhash, xmss):
        self.ots_key = xmss._index
        self.pubhash = self.generate_pubhash(xmss.pk())
        self.txhash = sha256(txhash + self.pubhash)

        self.txfrom = txfrom.encode('ascii')
        signature_components = xmss.SIGN(str(self.txhash))

        # signature_components = {i, s, auth_route, i_bms, self.pk(i), self.PK_short}
        self.i = signature_components[0]
        self.signature = signature_components[1]
        self.merkle_path = signature_components[2]
        self.i_bms = signature_components[3]
        self.pub = signature_components[4]
        self.PK = signature_components[5]

    def _validate_signed_hash(self):
        if not XMSS.VERIFY(message=self.txhash,
                           signature=[self.i, self.signature, self.merkle_path, self.i_bms, self.pub, self.PK]):
            logger.info('xmss_verify failed')
            return False

        if not XMSS.checkaddress(self.PK, self.txfrom):
            logger.info('Public key verification failed')
            return False

        return True

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> Transaction
        self.ots_key = int(dict_tx['ots_key'])
        self.nonce = int(dict_tx['nonce'])
        self.txfrom = dict_tx['txfrom'].encode('ascii')

        self.pubhash = dict_tx['pubhash'].encode('ascii')
        self.txhash = self._reformat(dict_tx['txhash'])
        self.i = int(dict_tx['i'])
        self.signature = self._reformat(dict_tx['signature'])
        self.merkle_path = self._reformat(dict_tx['merkle_path'])
        self.i_bms = self._reformat(dict_tx['i_bms'])
        self.pub = self._reformat(dict_tx['pub'])
        self.PK = self._reformat(dict_tx['PK'])
        return self

    def _reformat(self, srcList):
        destList = []
        if isinstance(srcList, list):
            for item in srcList:
                destList.append(self._reformat(item))
            return destList
        elif isinstance(srcList, unicode):
            return srcList.encode('ascii')

        return srcList

    def _validate_subtype(self, subtype, expected_subtype):
        if subtype != expected_subtype:
            logger.warning('Invalid subtype')
            logger.warning('Found: %s Expected: %s', subtype, expected_subtype)
            return False

        return True

    def get_message_hash(self):
        message = StringIO()
        # FIXME: This looks suspicious
        '''
        message.write(self.nonce)
        message.write(self.txfrom)
        message.write(self.txhash)
        message.write(self.i)
        message.write(self.signature)
        message.write(self.merkle_path)
        message.write(self.i_bms)
        message.write(self.pub)
        message.write(self.PK)
        message.write(self.subtype)
        '''
        return message

    def transaction_to_json(self):
        return json.dumps(self.__dict__)

    def json_to_transaction(self, dict_tx):
        return self._dict_to_transaction(json.loads(dict_tx))


class SimpleTransaction(Transaction):
    """
    SimpleTransaction for the transaction of QRL from one wallet to another.
    """

    def __init__(self):  # nonce removed..
        super(SimpleTransaction, self).__init__()
        self.subtype = TX_SUBTYPE_TX

    def get_message_hash(self):
        message = super(SimpleTransaction, self).get_message_hash()
        # message.write(self.epoch)
        # message.write(self.txto)
        # message.write(self.amount)
        # message.write(self.fee)
        message.write(self.txhash)
        return sha256(message.getvalue())

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> qrl.core.transaction.SimpleTransaction
        super(SimpleTransaction, self)._dict_to_transaction(dict_tx)
        self.txto = dict_tx['txto'].encode('ascii')
        self.amount = int(dict_tx['amount'])
        self.fee = int(dict_tx['fee'])
        self.txhash = dict_tx['txhash']  # FIXME: Repetition
        self.subtype = dict_tx['subtype'].encode('ascii')  # FIXME: Repetition
        return self

    def pre_condition(self, tx_state):
        # if state_uptodate() is False:
        #	logger.info(( 'Warning state not updated to allow safe tx validation, tx validity could be unreliable..'))
        #	return False
        tx_balance = tx_state[1]

        if self.amount < 0:
            logger.info('State validation failed for %s because: Negative send', self.txhash)
            return False

        if tx_balance < self.amount:
            logger.info('State validation failed for %s because: Insufficient funds', self.txhash)
            logger.info('balance: %s, amount: %s', tx_balance, self.amount)
            return False

        return True

    def create(self, tx_state, txto, amount, xmss, fee=0):
        self.txfrom = xmss.address
        self.txto = txto
        self.amount = int(amount)
        self.fee = int(fee)

        self.txhash = sha256(''.join(self.txfrom + self.txto + str(self.amount) + str(self.fee)))
        self.merkle_root = xmss.root
        if not self.pre_condition(tx_state):
            return False

        self._process_XMSS(self.txfrom, self.txhash, xmss)

        return self

    def validate_tx(self):
        if self.subtype != TX_SUBTYPE_TX:
            return False

        # sanity check: this is not how the economy is supposed to work!
        if self.amount <= 0:
            logger.info('State validation failed for %s because negative or zero', self.txhash)
            logger.info('Amount %d', self.amount)
            return False

        txhash = sha256(''.join(self.txfrom + self.txto + str(self.amount) + str(self.fee)))
        txhash = sha256(txhash + self.pubhash)

        # cryptographic checks
        if self.txhash != txhash:
            return False

        if not self._validate_signed_hash():
            return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def state_validate_tx(self, tx_state, transaction_pool):

        if not self.pre_condition(tx_state):
            return False

        pubhash = self.generate_pubhash(self.pub)

        tx_pubhashes = tx_state[2]
        if pubhash in tx_pubhashes:
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            pubhashn = self.generate_pubhash(txn.pub)
            if pubhashn == pubhash:
                logger.info('State validation failed for %s because: OTS Public key re-use detected', self.txhash)
                return False

        return True


class StakeTransaction(Transaction):
    """
    StakeTransaction performed by the nodes who would like
    to stake.
    """

    def __init__(self):
        super(StakeTransaction, self).__init__()
        self.subtype = TX_SUBTYPE_STAKE

    def get_message_hash(self):
        message = super(StakeTransaction, self).get_message_hash()
        # message.write(self.epoch)
        message.write(self.hash)
        message.write(str(self.first_hash))
        return sha256(message.getvalue())

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> qrl.core.transaction.StakeTransaction
        super(StakeTransaction, self)._dict_to_transaction(dict_tx)
        self.epoch = int(dict_tx['epoch'])
        self.balance = dict_tx['balance']
        self.hash = []

        for hash_item in dict_tx['hash']:
            self.hash.append(hash_item.encode('ascii'))
        self.first_hash = dict_tx['first_hash']

        if self.first_hash:
            self.first_hash = self.first_hash.encode('ascii')

        self.subtype = dict_tx['subtype'].encode('ascii')  # FIXME: Repetition (done in base class)
        return self

    def create(self, blocknumber, xmss, hashchain_terminator=None, first_hash=None, balance=None):
        if not balance:
            logger.info('Invalid Balance %d', balance)
            raise Exception

        self.epoch = blocknumber // config.dev.blocks_per_epoch  # in this block the epoch is..
        self.first_hash = first_hash
        self.balance = balance

        if hashchain_terminator is None:
            self.hash = HashChain(xmss).hashchain_reveal(epoch=self.epoch + 1)
        else:
            self.hash = hashchain_terminator

        self.txhash = ''.join(self.hash) + str(self.first_hash)
        self._process_XMSS(xmss.address, self.txhash, xmss)  # self.hash to be replaced with self.txhash
        return self

    def validate_tx(self):
        if not self._validate_subtype(self.subtype, TX_SUBTYPE_STAKE):
            return False

        if not helper.isValidAddress(self.txfrom):
            logger.info('Invalid From Address %s', self.txfrom)
            return False

        if self.first_hash:
            if sha256(self.first_hash) != self.hash[-1]:
                logger.info('First_hash doesnt stake to hashterminator')
                return False

        for i in range(len(self.hash)):
            self.hash[i] = str(self.hash[i])

        if not self._validate_signed_hash():
            return False

        return True

    def state_validate_tx(self, tx_state):
        if self.subtype != TX_SUBTYPE_STAKE:
            return False
        pub = self.pub
        pub = [''.join(pub[0][0]), pub[0][1], ''.join(pub[2:])]
        pubhash = sha256(''.join(pub))

        state_balance = tx_state[1]
        state_pubhashes = tx_state[2]

        if self.balance > state_balance:
            logger.info('Stake Transaction Balance exceeds maximum balance')
            logger.info('Max Balance Expected %d', state_balance)
            logger.info('Balance found %d', self.balance)
            return False

        if pubhash in state_pubhashes:
            logger.info('State validation failed for %s because: OTS Public key re-use detected', self.hash)
            return False

        return True


class CoinBase(Transaction):
    """
    CoinBase is the type of transaction to credit the block_reward to
    the stake selector who created the block.
    """

    def __init__(self):
        super(CoinBase, self).__init__()
        self.subtype = TX_SUBTYPE_COINBASE

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> qrl.core.transaction.CoinBase
        super(CoinBase, self)._dict_to_transaction(dict_tx)
        self.txto = dict_tx['txto'].encode('ascii')
        self.amount = int(dict_tx['amount'])
        self.txhash = dict_tx['txhash']  # FIXME: Repetition
        self.subtype = dict_tx['subtype'].encode('ascii')  # FIXME: Repetition
        return self

    def create(self, block_reward, block_headerhash, xmss):
        self.txto = self.txfrom = xmss.address
        self.amount = block_reward
        self.txhash = block_headerhash
        self._process_XMSS(self.txfrom, self.txhash, xmss)
        return self

    def validate_tx(self, block_headerhash):
        if self.txto != self.txfrom:
            logger.info('Non matching txto and txfrom')
            logger.info('txto: %s txfrom: %s', self.txto, self.txfrom)
            return False

        txhash = block_headerhash
        txhash = sha256(txhash + self.pubhash)

        if self.txhash != txhash:
            logger.info('Block_headerhash doesnt match')
            logger.info('Found: %s Expected: %s', self.txhash, block_headerhash)
            return False

        if not self._validate_signed_hash():
            return False

        return True


class LatticePublicKey(Transaction):
    """
    LatticePublicKey transaction to store the public key.
    This transaction has been designed for Ephemeral Messaging.
    """

    def __init__(self):
        super(LatticePublicKey, self).__init__()
        self.subtype = TX_SUBTYPE_LATTICE

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> LatticePublicKey
        super(LatticePublicKey, self)._dict_to_transaction(dict_tx)
        self.txhash = dict_tx['txhash']  # FIXME: Repetition
        self.subtype = dict_tx['subtype'].encode('ascii')  # FIXME: Repetition
        return self

    def create(self, xmss, kyber_pk, tesla_pk):
        self.txfrom = xmss.address
        self.kyber_pk = kyber_pk
        self.tesla_pk = tesla_pk
        self.txhash = sha256(self.kyber_pk + self.tesla_pk)
        self._process_XMSS(xmss.address, self.txhash, xmss)
        return self

    def validate_tx(self):
        if not self._validate_subtype(self.subtype, TX_SUBTYPE_LATTICE):
            return False

        txhash = sha256(self.kyber_pk + self.tesla_pk)
        txhash = sha256(txhash + self.pubhash)
        if self.txhash != txhash:
            logger.info('Invalid Txhash')
            logger.warning('Found: %s Expected: %s', self.txhash, txhash)
            return False

        if not self._validate_signed_hash():
            return False

        return True
