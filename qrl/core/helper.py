# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import jsonpickle
import simplejson as json

from qrl.core import config, logger


# noinspection PyClassHasNoInit
class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        return obj.__dict__


def json_encode_complex(obj):
    return json.dumps(obj, cls=ComplexEncoder)


def json_bytestream(obj):
    return json.dumps(obj.__dict__, cls=ComplexEncoder)


def json_bytestream_tx(tx_obj):  # JSON serialise tx object
    return json_bytestream(tx_obj)


def json_bytestream_pb(block_obj):
    return json_bytestream(block_obj)


def json_bytestream_bk(block_obj):  # "" block object
    return json_bytestream(block_obj)


def json_print(obj):  # prettify output from JSON for export purposes
    logger.info('%s', json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False))))


def json_print_telnet(obj):
    return json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False)), indent=4)


# Returns the number of blocks left before next epoch
def get_blocks_left(blocknumber):
    epoch = blocknumber // config.dev.blocks_per_epoch
    blocks_left = blocknumber - (epoch * config.dev.blocks_per_epoch)
    blocks_left = config.dev.blocks_per_epoch - blocks_left
    return blocks_left
