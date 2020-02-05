# coding=utf-8
import functools

from google.protobuf.json_format import MessageToJson, Parse
from pyqrllib.pyqrllib import shake128, bin2hstr

from qrl.core.config import DevConfig, user as user_config
from qrl.core.formulas import block_reward
from qrl.core.misc import ntp, logger
from qrl.crypto.Qryptonight import Qryptonight
from qrl.generated import qrl_pb2


class BlockHeader(object):
    def __init__(self, protobuf_blockheader=None):
        """
        >>> BlockHeader() is not None
        True
        """
        self._seed_hash = None
        self._seed_height = None
        self._data = protobuf_blockheader
        if protobuf_blockheader is None:
            self._data = qrl_pb2.BlockHeader()

    @property
    def pbdata(self):
        """
        Returns a protobuf object that contains persistable data representing this object
        :return: A protobuf BlockHeader object
        :rtype: qrl_pb2.BlockHeader
        """
        return self._data

    @property
    def block_number(self):
        return self._data.block_number

    @property
    def timestamp(self):
        return self._data.timestamp_seconds

    @property
    def headerhash(self):
        return self._data.hash_header

    @property
    def prev_headerhash(self):
        return self._data.hash_header_prev

    @property
    def block_reward(self):
        return self._data.reward_block

    @property
    def fee_reward(self):
        return self._data.reward_fee

    @property
    def tx_merkle_root(self):
        return self._data.merkle_root

    @property
    def extra_nonce(self):
        return self._data.extra_nonce

    @property
    def mining_nonce(self):
        return self._data.mining_nonce

    @staticmethod
    def nonce_offset(dev_config: DevConfig):
        return dev_config.mining_nonce_offset

    @staticmethod
    def extra_nonce_offset(dev_config: DevConfig):
        return dev_config.extra_nonce_offset

    def mining_blob(self, dev_config: DevConfig) -> bytes:
        blob = self.block_number.to_bytes(8, byteorder='big', signed=False) \
               + self.timestamp.to_bytes(8, byteorder='big', signed=False) \
               + self.prev_headerhash \
               + self.block_reward.to_bytes(8, byteorder='big', signed=False) \
               + self.fee_reward.to_bytes(8, byteorder='big', signed=False) \
               + self.tx_merkle_root

        # reduce mining blob: 1 byte zero + 4 bytes nonce + 8 bytes extra_nonce by pool + 5 bytes for pool (17 bytes)
        blob = bytes(shake128(dev_config.mining_blob_size_in_bytes - 18, blob))

        zero = 0
        blob = zero.to_bytes(1, byteorder='big', signed=False) + blob

        nonce_offset = self.nonce_offset(dev_config)
        if len(blob) < nonce_offset:
            raise Exception("Mining blob size below 56 bytes")

        # Now insert mining nonce and extra nonce in offset 56 for compatibility
        mining_nonce_bytes = \
            self.mining_nonce.to_bytes(4, byteorder='big', signed=False) + \
            self.extra_nonce.to_bytes(8, byteorder='big', signed=False) + \
            zero.to_bytes(5, byteorder='big', signed=False)

        blob = blob[:nonce_offset] + mining_nonce_bytes + blob[nonce_offset:]

        return bytes(blob)

    @staticmethod
    @functools.lru_cache(maxsize=5)
    def _get_qryptonight_hash(block_number, seed_height, seed_hash, blob):
        qn = Qryptonight()
        qnhash = bytes(qn.hash(block_number, seed_height, seed_hash, blob))
        return qnhash

    def generate_headerhash(self, dev_config: DevConfig):
        return self._get_qryptonight_hash(self.block_number,
                                          self._seed_height,
                                          self._seed_hash,
                                          self.mining_blob(dev_config))

    @staticmethod
    def create(dev_config: DevConfig,
               blocknumber: int,
               prev_headerhash: bytes,
               prev_timestamp: int,
               hashedtransactions: bytes,
               fee_reward: int,
               seed_height: int,
               seed_hash: bytes):
        bh = BlockHeader()
        bh._data.block_number = blocknumber

        if bh._data.block_number != 0:
            bh._data.timestamp_seconds = int(ntp.getTime())
            # If current block timestamp is less than or equals to the previous block timestamp
            # then set current block timestamp 1 sec higher than prev_timestamp
            if bh._data.timestamp_seconds <= prev_timestamp:
                bh._data.timestamp_seconds = prev_timestamp + 1
            if bh._data.timestamp_seconds == 0:
                logger.warning('Failed to get NTP timestamp')
                return
        else:
            bh._data.timestamp_seconds = prev_timestamp  # Set timestamp for genesis block

        bh._data.hash_header_prev = prev_headerhash
        bh._data.merkle_root = hashedtransactions
        bh._data.reward_fee = fee_reward

        bh._data.reward_block = bh.block_reward_calc(blocknumber, dev_config)

        bh._seed_hash = seed_hash
        bh._seed_height = seed_height
        bh.set_nonces(dev_config, 0, 0)
        return bh

    def update_merkle_root(self, dev_config: DevConfig, hashedtransactions: bytes):
        self._data.merkle_root = hashedtransactions
        self.set_nonces(dev_config, 0, 0)

    def set_nonces(self, dev_config: DevConfig, mining_nonce, extra_nonce=0):
        self._data.mining_nonce = mining_nonce
        self._data.extra_nonce = extra_nonce
        self._data.hash_header = self.generate_headerhash(dev_config)

    def set_mining_nonce_from_blob(self, blob, dev_config: DevConfig):
        nonce_offset = self.nonce_offset(dev_config)
        extra_nonce_offset = self.extra_nonce_offset(dev_config)

        mining_nonce_bytes = blob[nonce_offset: nonce_offset + 4]
        mining_nonce = int.from_bytes(mining_nonce_bytes, byteorder='big', signed=False)

        extra_nonce_bytes = blob[extra_nonce_offset: extra_nonce_offset + 8]
        extra_nonce = int.from_bytes(extra_nonce_bytes, byteorder='big', signed=False)

        self.set_nonces(dev_config, mining_nonce, extra_nonce)

    @staticmethod
    def block_reward_calc(block_number, dev_config: DevConfig):
        """
        return block reward for the block_n
        :return:
        """
        if block_number == 0:
            return dev_config.supplied_coins
        return int(block_reward(block_number, dev_config))

    def validate(self, fee_reward, coinbase_amount, tx_merkle_root, dev_config: DevConfig):
        current_time = ntp.getTime()
        allowed_timestamp = current_time + dev_config.block_lead_timestamp
        if self.timestamp > allowed_timestamp:
            logger.warning('BLOCK timestamp is more than the allowed block lead timestamp')
            logger.warning('Block timestamp %s ', self.timestamp)
            logger.warning('threshold timestamp %s', allowed_timestamp)
            return False

        if self.timestamp < user_config.genesis_timestamp:
            logger.warning('Timestamp lower than genesis timestamp')
            logger.warning('Genesis Timestamp %s', user_config.genesis_timestamp)
            logger.warning('Block Timestamp %s', self.timestamp)
            return False

        generated_hash = self.generate_headerhash(dev_config)
        if generated_hash != self.headerhash:
            logger.warning('received:   {}'.format(bin2hstr(self.headerhash)))
            logger.warning('calculated: {}'.format(bin2hstr(generated_hash)))
            logger.warning('Headerhash false for block: failed validation')
            return False

        if self.block_reward != self.block_reward_calc(self.block_number, dev_config):
            logger.warning('Block reward incorrect for block: failed validation')
            return False

        if self.fee_reward != fee_reward:
            logger.warning('Block Fee reward incorrect for block: failed validation')
            return False

        if self.block_reward + self.fee_reward != coinbase_amount:
            logger.warning('Block_reward + fee_reward doesnt sums up to coinbase_amount')
            return False

        if self.tx_merkle_root != tx_merkle_root:
            logger.warning('Invalid TX Merkle Root')
            return False

        return True

    def validate_parent_child_relation(self, parent_block):
        if not parent_block:
            logger.warning('Parent Block not found')
            return False

        if parent_block.block_number != self.block_number - 1:
            logger.warning('Block numbers out of sequence: failed validation')
            return False

        if parent_block.headerhash != self.prev_headerhash:
            logger.warning('Headerhash not in sequence: failed validation')
            return False

        if self.timestamp <= parent_block.timestamp:
            logger.warning('BLOCK timestamp must be greater than parent block timestamp')
            logger.warning('block timestamp %s ', self.timestamp)
            logger.warning('must be greater than %s', parent_block.timestamp)
            return False

        return True

    @staticmethod
    def from_json(json_data):
        pbdata = qrl_pb2.BlockHeader()
        Parse(json_data, pbdata)
        return BlockHeader(pbdata)

    def verify_blob(self, blob: bytes, dev_config: DevConfig) -> bool:
        mining_nonce_offset = dev_config.mining_nonce_offset
        blob = blob[:mining_nonce_offset] + blob[mining_nonce_offset + 17:]

        actual_blob = self.mining_blob(dev_config)
        actual_blob = actual_blob[:mining_nonce_offset] + actual_blob[mining_nonce_offset + 17:]

        if blob != actual_blob:
            return False

        return True

    def to_json(self):
        # FIXME: Remove once we move completely to protobuf
        return MessageToJson(self._data, sort_keys=True)
