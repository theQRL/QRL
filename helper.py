import jsonpickle
import simplejson as json
from merkle import sha256
import block
import merkle
import configuration as c

# simple transaction creation and wallet functions using the wallet file..

def select_target_hashchain(last_block_headerhash):
    target_chain = 0
    for byte in last_block_headerhash:
        target_chain += ord(byte)

    target_chain = (target_chain - 1) % (c.hashchain_nums - 1)  # 1 Primary hashchain size

    return target_chain

def wlt():
    return merkle.numlist(wallet.list_addresses())


def xmss_rootoaddr(PK_short):
    return 'Q' + sha256(PK_short[0] + PK_short[1]) + sha256(sha256(PK_short[0] + PK_short[1]))[:4]


def xmss_checkaddress(PK_short, address):
    if 'Q' + sha256(PK_short[0] + PK_short[1]) + sha256(sha256(PK_short[0] + PK_short[1]))[:4] == address:
        return True
    return False


def roottoaddr(merkle_root):
    return 'Q' + sha256(merkle_root) + sha256(sha256(merkle_root))[:4]


def checkaddress(merkle_root, address):
    if 'Q' + sha256(merkle_root) + sha256(sha256(merkle_root))[:4] == address:
        return True
    return False


def json_decode_block(json_block):
    myBlock = block.Block()
    myBlock.json_to_block(json.loads(json_block))
    return myBlock


def json_encode(obj):
    return json.dumps(obj)


def json_decode(js_obj):
    return json.loads(js_obj)


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


def json_bytestream_ph(mini_block):
    return json_encode(mini_block)


def json_bytestream_bk(block_obj):  # "" block object
    return json_bytestream(block_obj)


def json_print(obj):  # prettify output from JSON for export purposes
    printL((json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False)), indent=4)))


def json_print_telnet(obj):
    return json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False)), indent=4)

def hash_to_terminator(hash_val, times):
    new_hash = hash_val
    for i in range(times):
        new_hash = sha256(new_hash)
    return new_hash

def reveal_to_terminator(hash_val, times):
    return hash_to_terminator(hash_val, times + 1)