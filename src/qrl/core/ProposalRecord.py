from collections import namedtuple

from qrl.generated import qrl_pb2
from qrl.core.misc import logger
from qrl.core.State import State


class ProposalRecord:
    def __init__(self, protobuf_block=None):
        self._data = protobuf_block
        if protobuf_block is None:
            self._data = qrl_pb2.ProposalRecord()

        counter_mapping = namedtuple("counter_mapping", ["get", "update"])

        self._counter_by_name = {
            b'p_proposal_tx_hash': counter_mapping(self.number_of_tx_hashes,
                                                   self.update_number_of_tx_hashes),
        }

    def pbdata(self):
        return self._data

    def get_counter_by_name(self, name: bytes):
        return self._counter_by_name[name].get()

    def update_counter_by_name(self, name, value=1, subtract=False):
        self._counter_by_name[name].update(value, subtract)

    def number_of_tx_hashes(self):
        return self._data.number_of_tx_hashes

    def update_number_of_tx_hashes(self, value=1, subtract=False):
        if subtract:
            self._data.number_of_tx_hashes -= value
        else:
            self._data.number_of_tx_hashes += value

    def serialize(self):
        return self._data.SerializeToString()

    @staticmethod
    def deserialize(data):
        pbdata = qrl_pb2.ProposalRecord()
        pbdata.ParseFromString(bytes(data))
        return ProposalRecord(pbdata)

    @staticmethod
    def put_state(state: State, key, proposal_record, batch):
        try:
            state._db.put_raw(key, proposal_record.serialize(), batch)
        except Exception as e:
            raise Exception("[ProposalRecord] Exception in put_state %s", e)

    @staticmethod
    def get_state(state: State, key: bytes):
        try:
            data = state._db.get_raw(key)
            return ProposalRecord.deserialize(data)
        except KeyError:
            logger.debug('[get_state] ProposalRecord not found')
        except Exception as e:
            logger.error('[get_state] %s', e)

        return ProposalRecord()

    @staticmethod
    def get_key(block_number, activation_delay):
        """
            activation_block_number is the block number after which config will be activated
            so an activation block number 10 means the config will be activated only after adding
            block number 10 into the block chain
        """
        activation_block_number = block_number + activation_delay
        return b'proposal_record_block_number_' + activation_block_number.to_bytes(8, byteorder='big', signed=False)
