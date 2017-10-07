# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from abc import ABCMeta

import simplejson as json
from io import StringIO

import qrl
from pyqrllib.pyqrllib import sha2_256, getAddress, hstr2bin, bin2hstr, str2bin
from qrl.core import helper, config, logger
from qrl.core.Transaction_subtypes import *
from qrl.crypto.hashchain import hashchain_reveal
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS


class Transaction(object, metaclass=ABCMeta):
    """
    Abstract Base class to be derived by all other transactions
    """

    # FIXME: Use metaclass and make this class abstract. Enforce same API in derived classes

    def __init__(self):
        self.nonce = 0  # Nonce is set when block is being created
        self.ots_key = None
        self.pubhash = None
        self.txhash = None
        self.txfrom = None

        self.PK = None
        self.signature = None

    @staticmethod
    def tx_id_to_name(id):
        id_name = {
            1: 'TX',
            2: 'STAKE',
            3: 'COINBASE',
            4: 'LATTICE'
        }
        return id_name[id]

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

        subtype = txdict['subtype']

        return type_to_txn[subtype]()._dict_to_transaction(txdict)

    @staticmethod
    def generate_pubhash(pub, ots_key):
        return sha256(pub + tuple([int(char) for char in str(ots_key)]))

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
        self.ots_key = xmss.get_index()
        self.pubhash = self.generate_pubhash(xmss.pk(), self.ots_key)
        self.txhash = sha2_256(txhash + self.pubhash)
        self.txfrom = txfrom

        self.PK = xmss.pk()
        self.signature = xmss.SIGN(self.txhash)

    def _validate_signed_hash(self, height=config.dev.xmss_tree_height):
        if self.subtype != TX_SUBTYPE_COINBASE and getAddress('Q', self.PK) != self.txfrom:
            logger.warning('Public key verification failed')
            return False

        if not XMSS.VERIFY(message=self.txhash,
                           signature=self.signature,
                           pk=self.PK,
                           height=height):
            logger.warning('xmss_verify failed')
            return False

        return True

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> Transaction
        self.subtype = dict_tx['subtype']

        self.ots_key = int(dict_tx['ots_key'])
        self.nonce = int(dict_tx['nonce'])
        self.txfrom = dict_tx['txfrom']

        self.pubhash = tuple(dict_tx['pubhash'])
        self.txhash = tuple(dict_tx['txhash'])

        self.PK = tuple(dict_tx['PK'])
        self.signature = tuple(dict_tx['signature'])
        return self

    def _reformat(self, srcList):
        destList = []
        if isinstance(srcList, list):
            for item in srcList:
                destList.append(self._reformat(item))
            return destList
        elif isinstance(srcList, str):
            return srcList

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
        message.write(self.signature)
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
        message.write(str(self.signature))
        message.write(str(self.txhash))
        return sha256(bytes(message.getvalue(), 'utf-8'))

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> qrl.core.transaction.SimpleTransaction
        super(SimpleTransaction, self)._dict_to_transaction(dict_tx)
        self.txto = dict_tx['txto']
        self.amount = int(dict_tx['amount'])
        self.fee = int(dict_tx['fee'])
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
        self.txfrom = xmss.get_address()
        self.txto = txto.decode('ascii')
        self.amount = int(amount)
        self.fee = int(fee)

        # FIXME: This is very confusing and can be a security risk
        self.txhash = sha256(bytes(''.join(self.txfrom + self.txto + str(self.amount) + str(self.fee)), 'utf-8'))
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

        txhash = sha256(bytes(''.join(self.txfrom + self.txto + str(self.amount) + str(self.fee)), 'utf-8'))
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

        pubhash = self.generate_pubhash(self.PK, self.ots_key)

        tx_pubhashes = tx_state[2]

        if pubhash in tx_pubhashes:
            logger.info('1. State validation failed for %s because: OTS Public key re-use detected', self.txhash)
            return False

        for txn in transaction_pool:
            if txn.txhash == self.txhash:
                continue

            pubhashn = self.generate_pubhash(txn.PK, txn.ots_key)
            if pubhashn == pubhash:
                logger.info('2. State validation failed for %s because: OTS Public key re-use detected', self.txhash)
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
        """
        :return:
        :rtype:
        >>> s = StakeTransaction()
        >>> seed = [i for i in range(48)]
        >>> slave = XMSS(4, seed)
        >>> t = s.create(0, XMSS(4, seed), slave.pk(), None, slave.pk(), 10)
        >>> t.get_message_hash()
        (190, 216, 197, 106, 146, 168, 148, 15, 12, 106, 8, 196, 43, 74, 14, 144, 215, 198, 251, 97, 148, 8, 182, 151, 10, 227, 212, 134, 25, 11, 228, 245)
        """
        message = super(StakeTransaction, self).get_message_hash()
        # message.write(self.epoch)

        tmphash = ''.join([bin2hstr(b) for b in self.hash])
        message.write(tmphash)
        message.write(bin2hstr(self.first_hash))
        messagestr = message.getvalue()
        result = sha256(str2bin(messagestr))
        return result

    def _dict_to_transaction(self, dict_tx):
        # type: (dict) -> qrl.core.transaction.StakeTransaction
        super(StakeTransaction, self)._dict_to_transaction(dict_tx)
        self.epoch = int(dict_tx['epoch'])
        self.balance = dict_tx['balance']

        self.slave_public_key = tuple(dict_tx['slave_public_key'])

        self.hash = []

        for hash_item in dict_tx['hash']:
            self.hash.append(tuple(hash_item))

        self.first_hash = tuple(dict_tx['first_hash'])

        return self

    def create(self, blocknumber, xmss, slave_public_key, hashchain_terminator=None, first_hash=None, balance=None):
        """
        :param blocknumber:
        :type blocknumber:
        :param xmss:
        :type xmss:
        :param slave_public_key:
        :type slave_public_key:
        :param hashchain_terminator:
        :type hashchain_terminator:
        :param first_hash:
        :type first_hash:
        :param balance:
        :type balance:
        :return:
        :rtype:
        >>> s = StakeTransaction()
        >>> slave = XMSS(4)
        >>> isinstance(s.create(0, XMSS(4), slave.pk(), None, slave.pk(), 10), StakeTransaction)
        True
        """
        if not balance:
            logger.info('Invalid Balance %d', balance)
            raise Exception

        self.slave_public_key = slave_public_key
        self.epoch = blocknumber // config.dev.blocks_per_epoch  # in this block the epoch is..
        self.first_hash = first_hash
        self.balance = balance

        if hashchain_terminator is None:
            self.hash = hashchain_reveal(xmss.get_seed_private(), epoch=self.epoch + 1)
        else:
            self.hash = hashchain_terminator

        tmphash = ''.join([bin2hstr(b) for b in self.hash])

        if self.first_hash is None:
            self.first_hash = tuple()

        self.txhash = str2bin(tmphash + bin2hstr(self.first_hash) + bin2hstr(self.slave_public_key))
        self._process_XMSS(xmss.get_address(), self.txhash, xmss)  # self.hash to be replaced with self.txhash
        return self

    def validate_tx(self):
        if not self._validate_subtype(self.subtype, TX_SUBTYPE_STAKE):
            return False

        if not helper.isValidAddress(self.txfrom):
            logger.info('Invalid From Address %s', self.txfrom)
            return False

        if self.first_hash:
            hashterminator = sha256(self.first_hash)
            if hashterminator != self.hash[-1]:
                logger.info('First_hash doesnt stake to hashterminator')
                return False

        if not self._validate_signed_hash():
            return False

        return True

    def state_validate_tx(self, tx_state):
        if self.subtype != TX_SUBTYPE_STAKE:
            return False

        state_balance = tx_state[1]
        state_pubhashes = tx_state[2]

        if self.balance > state_balance:
            logger.info('Stake Transaction Balance exceeds maximum balance')
            logger.info('Max Balance Expected %d', state_balance)
            logger.info('Balance found %d', self.balance)
            return False

        # TODO no need to transmit pubhash over the network
        # pubhash has to be calculated by the receiver
        if self.pubhash in state_pubhashes:
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
        self.txto = dict_tx['txto']
        self.amount = int(dict_tx['amount'])
        return self

    def create(self, blockheader, xmss):
        self.txfrom = blockheader.stake_selector
        self.txto = blockheader.stake_selector
        self.amount = blockheader.block_reward + blockheader.fee_reward

        self.txhash = blockheader.prev_blockheaderhash + tuple([int(char) for char in str(blockheader.blocknumber)]) + blockheader.headerhash
        self._process_XMSS(self.txfrom, self.txhash, xmss)
        return self

    def validate_tx(self, chain, blockheader):
        sv_list = chain.block_chain_buffer.stake_list_get(blockheader.blocknumber)
        if blockheader.blocknumber > 1 and sv_list[self.txto].slave_public_key != self.PK:
            logger.warning('Stake validator doesnt own the Public key')
            logger.warning('Expected public key %s', sv_list[self.txto].slave_public_key)
            logger.warning('Found public key %s', self.PK)
            return False

        if self.txto != self.txfrom:
            logger.warning('Non matching txto and txfrom')
            logger.warning('txto: %s txfrom: %s', self.txto, self.txfrom)
            return False

        txhash = blockheader.prev_blockheaderhash + tuple([int(char) for char in str(blockheader.blocknumber)]) + blockheader.headerhash
        txhash = sha256(txhash + self.pubhash)

        if self.txhash != txhash:
            logger.warning('Block_headerhash doesnt match')
            logger.warning('Found: %s', self.txhash)
            logger.warning('Expected: %s', txhash)
            return False

        #Slave XMSS is used to sign COINBASE txn having quite low XMSS height
        if not self._validate_signed_hash(height=config.dev.slave_xmss_height):
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
        return self

    def create(self, xmss, kyber_pk, tesla_pk):
        self.txfrom = xmss.get_address()
        self.kyber_pk = kyber_pk
        self.tesla_pk = tesla_pk
        self.txhash = sha256(self.kyber_pk + self.tesla_pk)
        self._process_XMSS(xmss.get_address(), self.txhash, xmss)
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

class DuplicateTransaction:
    def __init__(self):
        self.blocknumber = 0
        self.prev_blockheaderhash = None

        self.coinbase1 = None
        self.headerhash1 = None

        self.coinbase2 = None
        self.headerhash2 = None

        self.subtype = TX_SUBTYPE_DUPLICATE

    def get_message_hash(self):
        return self.headerhash1 + self.headerhash2

    def create(self, block1, block2):
        self.blocknumber = block1.blockheader.blocknumber
        self.prev_blockheaderhash = block1.blockheader.prev_blockheaderhash

        self.coinbase1 = block1.transactions[0]
        self.headerhash1 = block1.blockheader.headerhash
        self.coinbase2 = block2.transactions[0]
        self.headerhash2 = block2.blockheader.headerhash

        return self

    def validate_tx(self):
        if self.headerhash1 == self.headerhash2 and self.coinbase1.signature == self.coinbase2.signature:
            logger.info('Invalid DT txn')
            logger.info('coinbase1 and coinbase2 txn are same')
            return

        if not self.validate_hash(self.headerhash1, self.coinbase1):
            return

        if not self.validate_hash(self.headerhash2, self.coinbase2):
            return

        return True

    def validate_hash(self, headerhash, coinbase):
        txhash = self.prev_blockheaderhash + tuple([int(char) for char in str(self.blocknumber)]) + headerhash
        txhash = sha256(txhash + coinbase.pubhash)

        if coinbase.txhash != txhash:
            logger.info('Invalid Txhash')
            logger.warning('Found: %s Expected: %s', coinbase.txhash, txhash)
            return False

        if not coinbase._validate_signed_hash(height=config.dev.slave_xmss_height):
            return False

        return True

    def to_json(self):
        return helper.json_encode_complex(self)

    def _dict_to_transaction(self, dict_tx):
        self.blocknumber = dict_tx['blocknumber']
        self.prev_blockheaderhash = tuple(dict_tx['prev_blockheaderhash'])

        self.coinbase1 = CoinBase()._dict_to_transaction(dict_tx['coinbase1'])
        self.headerhash1 = tuple(dict_tx['headerhash1'])

        self.coinbase2 = CoinBase()._dict_to_transaction(dict_tx['coinbase2'])
        self.headerhash2 = tuple(dict_tx['headerhash2'])

        return self

    def json_to_transaction(self, str_tx):
        return self._dict_to_transaction(json.loads(str_tx))

    def from_txdict(self, dict_tx):
        return self._dict_to_transaction(dict_tx)
