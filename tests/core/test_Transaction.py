from unittest import TestCase

import simplejson as json
from mock import Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.misc import logger
from qrl.core.BlockHeader import BlockHeader
from qrl.core.Transaction import Transaction, TransferTransaction, CoinBase, TokenTransaction, TransferTokenTransaction
from qrl.crypto.misc import sha256
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2

logger.initialize_default()

test_json_Simple = """{
  "type": "TRANSFER",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "fee": "1",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "sTAdNZQIP4PEE90Kyr2NWQEkBU9QV5hFSFVv4UEY9xQ=",
  "transfer": {
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "100"
  }
}"""

test_json_Stake = """{
  "type": "STAKE",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "zsgkQV5T6NxYlI8k/6uGQ2yaiQ41bHfcEIRhHN/sINE=",
  "stake": {
    "activationBlocknumber": "2",
    "slavePK": "OAeT3r+PcucO9zUe5QBd9sfKIyD/SeDq0MQLGce7HMFJbhmkgsBjUL3AVOTtUqJOyMmUxE+TQdARkKgasJOt6A==",
    "hash": "H5NgPbU7+tXJI5D3NdDLuGF7SrghSukcVmSj0emwCcg="
  }
}"""

test_json_CoinBase = """{
  "type": "COINBASE",
  "addrFrom": "UTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OQ==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "GZLL6A/bnHblAz0ObQVHzK2kZQGc8cMcfVg87zKAETQ=",
  "coinbase": {
    "addrTo": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
    "amount": "90",
    "blockNumber": "1",
    "headerhash": "cbyk7G3tHwuys91Ox27qL/Y/kPtS8AG7vvGx1bntChk="
  }
}"""

test_json_Vote = """{
  "type": "VOTE",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "LlUkRnUJbYidP6hPWA5Rt+7U7ddy+++Ppz5HgWSild4=",
  "vote": {
    "blockNumber": "10",
    "hashHeader": "cbyk7G3tHwuys91Ox27qL/Y/kPtS8AG7vvGx1bntChk="
  }
}"""

test_json_Token = """{
  "type": "TOKEN",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "fee": "1",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "yMLY+Y3J0p0Wj5NFDYZb1PuAbnZKaLCx2cGIDZic9R8=",
  "token": {
    "symbol": "UVJM",
    "name": "UXVhbnR1bSBSZXNpc3RhbnQgTGVkZ2Vy",
    "owner": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
    "decimals": "4",
    "initialBalances": [
      {
        "address": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
        "amount": "400000000"
      },
      {
        "address": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
        "amount": "200000000"
      }
    ]
  }
}"""

test_json_TransferToken = """{
  "type": "TRANSFERTOKEN",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "fee": "1",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "fyjill4aCcMTmXBOtYFKyo6XOod1hXCuHG7Qg6JILpc=",
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAw",
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "200000"
  }
}"""

test_signature_Simple = (
    b'\x00\x00\x00\nqv\xfaUe\xc5\x9a\x87uz\xc3\xa3\xc4^D\x84z\xd2\x98\xce'
    b'"(\x08\x9a\x1c\x9e\x0b"\xc5@\x9e\xc2\x93#\xbb2\xca\x19\xa4!\xc5d\x90\xc8'
    b'u\xc9\xe6\xa9\xc6\xe2\xf3\xdc\x8f\xd9\x18\xf8W0\xd8\x02\xb5\x98\x1fh'
    b'V&\x90\x95\x0f\xd6\xc1\xa1\xdb\x05\xaeo3\x1e\xbbLF=\x99\xb0|\xa2_"'
    b'\x11\xb8\x9ea\x95\xb0`\x05V\\B\xf5\xb0;CiO\x8dk\x11or\xcd\x03\x0fP\xd3\\'
    b'\xea<\x83\xbaw4\xf7B\xe4\x82\x8eA\xb1\xd1Ty,\xcdf\x0c$\x01VA\x8d\xcb\xe8\xa8'
    b'}\x01&\x16\xa4Y`i#/\xf1\xba\x18\x9c\xa0\x91\xc3Fi\x80G\xb8\xab\x99\xd5d\t;'
    b'\x0b\xbc\x91n\t<\x99Q\x00\xabbT\xb0/\xcb\xff\xd0o\xcd\xc1\xee`+gnJ[\x02'
    b'\xac\x1f\xd9t2\x07\x914\xe1\xc1\x943\xb6\xaa\x00%\x87\xf6\x0c\x8c'
    b'\xfd\x91\xaat\x97\xc7\xcc]\x83\x04\xae\x8c\xae3gE/\xd6\x81 Pz\xde\x0e'
    b'\x05\x7fX\x9bv\xaa\xc9\xa1\x07Z\x87d\x88\x83a\x82O\x04\xddS\x80m\t\xf3'
    b's\xf9e~\x8f\x13a~d\x15\xf9\xf7F\xe8M\xf9c\x0f\xec\xe3\xfc\tV\x0e\x18\xd8aj'
    b'K\xcb\x07\x1d\xe3\xe0\xcb\xd5\xcf\xf6)\x9dh\xc6\xc5\xbb\xc8\xab}E7>\x99\x13'
    b'd\xd7\x0f\x8a\xef\xaa\x94\x88\x04N\xac w\xcdC\xd2\xb2\xf2\\~pN\xc6\x1e'
    b'\x03Jl\xbb\xbb]\xd7\x0b\x89\x1do\\<\x9a\xf8\x89\x13\xa2s(\xbfR\xee\x0c'
    b"\xe7K\x1e\x90\xcb\xc5\x17\x15\xffD\xc8\xaaS'\xc5\xa3w\xe5\xdcF#QR\xff"
    b'?9\xc5\x1f\x91 \x0e\xf1?\x10\xf4\x03C\xce\x0e\xf5\xb5bK\x963\xa8\x1c\xa8'
    b'\xe08\xbf\xbb\x17\x07\xbf;js\xca\xd7\xf16+\xc7\x99\x1c\x8f\xb8\xe93\xf2\xe5'
    b'\x16?YD\x7f\xceX\xf4\x19t\x9bR\xcba\xab1\t\xf9\xdf\xac\x83\x1f"a'
    b'\xe9\xf3_\x90\xe9-\xe9c\xf1\xa5\x0c\x14\xb1\xbfK\xa2\xbe0brn\x1f\x07\x90'
    b'\xf7\xe4*\xea\xfc\x92>\xc3d\xb6\x0cS~\x17T\\\x9c \xef\x0c\xa7{\xcd\xf3'
    b'\x07\xba\xe5\x1a\xbfb\xab\xad\xd1R\xdaN\xea\x08\n\xf1\x7f\x11\x90\xed'
    b'\x1d\xcaeBxi\x08Q\x8aD\x97\x1a\x1a\xe0$#\xd4/\xf4~D\x8d\x94b\r\xb6\r\xc5'
    b'zo\xd9C\xe5\x83\x8f\x9b\xfaM\xf9\xd9}\x8f\xcaR\xb1\x99\x86\x97\xd1\xc3\t\xe7'
    b'\xfb\xda\xb3\xc4\x02\xb5s\x90K\x12\x9e\xe9$\x98n\xdaJ\r\x00\x9f]ph\x80'
    b'\xb7a({\x14\xce\xdb*\xb1\xe3\xc5\x92\x82\xff.\xf5\xf1Wxr\xff\x9ej\xb6'
    b'\xb9\x03\xe6w`\xcd\xb0\xe3\xb5\xda\x80\x10n\xfc\xaa\x1c|\x8bg\x9bx\x01$\xfd'
    b'F\x9b+i\xef\x8fo>\x91\xc2\xa9v\xe0\x8c\xc9\xd9\n\xfc\xf3\xed-q\x9a\x9a'
    b'\x94\xdc*\xcc\xcfX8[\x90e\xc3\xa1\xab\xe2\x84\xaf\xc8\xc9{\xea\x93\xf0\x83z'
    b'\xaf\xcd\x89\x10\x95\x05\xdc\x82\xfa\xbb\xb2\xd3L1)|\xb65\xc5\x00'
    b'\x8f\xea\x1e_e@\xde&x[\xf30Bf\x95\xbd:\xcb\x08}G\xc6\x968\xa8e\x18\xa1'
    b'r\xd6\x13\xaa$\xed\xcd\xb1\xc5\x00\xb5\xd1\xc2\xf1Z\xad\xac\xed*\x08'
    b'\xa2\x01\xf5\x84\t\xc5\x8a\xc3\r\xf8\x9e\xb1\x1d\x1eE0\xd9L\t\x15'
    b'\xeb\xd4\r\xe7f\xd2\xb7\xd4\xf8%[T\xdf\xc2\x9d\xa7 \xd6\xf9K`\xe0\x0b\xd0'
    b'J\xe2\x92\xec \xe7\x8d\xb1\xa0\x06\x0c\r!]kn|;r\\\xd7Sw!r\xd0\x00")Y\x08\x9d'
    b'\x02Qj\xa9\xa9l\xd7\xd0\xc61\x83\xe0\xe1((\x03\xfa\x06\xa3\xd5\xb9\x80oq'
    b' hf\x08\xd7\xe1\x878y\x13\xf6\xa9\xb3z\xdf\xb6L\xff\xff\x9e\xa1\x88PF'
    b'\xb4\x05\x84\x85\xf0\x0eel\x84\xa6nE\x1bu\xd8\xeb\x13\xf5\x80\xd5\xd02QO'
    b"\x7fm$\xads\x9e\x04_\xfd\xc9'\xc5\xfbZ\x02;\xc1\xd0\td\xf1\xa9\xa3O"
    b'G\x80\x11t\xc8]\x80\x9c\xf9\xf7\xd2P\xe2\xbb\xf1:\x07\xad\xd1\xb3\x88\xbeK\n'
    b'Q>\\t\x07\xcf\xc3\x83Rw]@\xcbz2\xeb\xc6\x1bN;!\xcb\xacn\x8e\xb7\x11\x15'
    b'\xbe9\x80$@\xdb\xbc\xbau\xb8@\xde|#a\xe4=\xa8\x04\x13\x81\xba\xd9h'
    b'B\xea\x8a\x93j\x06\xaa8\x83\x01v\xfbL@\x9f\xc1\x83D\\\xf6b\xbfN~ B\x02?'
    b'\x98H~\x15AK\x10\xa7M\xce,E\xceRN&\x03\x8a\xed\t}\xba{`\x159\\\xed\xf1EM\xd8'
    b'u\xf7\\(j\xe0\x02\x87-:G)\xe9l\xec\x15\x9c\x91\xf6\xa4\r\x11"J\x19H\x8ei'
    b'\xdb\x87L\x8b\x91\xfa(\x01\xcb\x8b\xa95\xa6\xc6\xb5\xd9\xbai\xad9\xf1dN\xf4'
    b'\x8dkE\x18\xaf\xdb\xad\x94>\x06.\x0c\x81\x9a\x92j\x86\x94^\xbaCe\xb5\x17'
    b'\xe6\x10&;\xdc$\x87\x82\xc6\xc0\x08\xb8\xf62\xe5\xbf!\xda/\xe2'
    b'\x93\x0f\x87\x12s\xca\xb5f?\x94C\x13\xd9b\xa0C\xa8\xfa\xda\x17\x7f\x16C\xa6'
    b'\x99\xcc\xf6\xa2\xf9?\x11\xcb\xc9\xb5\x8a\xac\x803\x9a\xcb\xc0T\xbf\xc6'
    b'\xf9\xb5\xcaO\xa9s\xd7P\x0b\x81\xf7\x8d6\x1e\x1a\xc6\x9a\x8b"\x89'
    b'R\xde\x8f\xd6p\x99\x97\xcbt|\xc9\x9b\xb7:\xed\xd86p\x89l\x91\x08\x8c\xa2'
    b'\x06\x11\x83\x90|\x195\xf4\xa1\xfc\xe5\r\xfd\xe2\x1f\xf3\xdc\t&\xf9"W\x88%'
    b'\x84\x94\xecL&%\xca!\xbd\xe4q2\xc7]\x84d\xd5\xf2\x80^Nv6D\t\x18\xde_'
    b"\xf5;\xf5Wkj\x17,\xc0'\xd3\xe7\xd9\xe7a\xc5\x11\xea\xbdA\xb9\xdd\xa9^"
    b'\xd9\x07\xb1l\xda\xe7\x9b\xd7\xf6\xf4\xd8\xdf\xb5g\xff\xc0\xa6\xc7yV'
    b'iY\xc9\xdb\xe9\xa7\x17\xe2\xe6\xa1\xfa\x9bX\x8d\xc8\xdb^+\x7f\xac'
    b'\xad\xea\x82V&\xa0Y\xcdh\xbf\x8c\xeb\xa8\xba[SK\x18!\xbb,\x96p\xdaC\xe9\xdbU'
    b'\x9a\x94\xde\x8d\xca\x18j\x82\xceh\xd5\xb1\x8f\x03+Z\xd3>s\x03\xc3\x11\tA'
    b'\x8ew\xd93l\x0f\xcd\x13\xf57\xf7\xa8\x05`]\xae\x1e1Y\xba\xc9\xf2\n\xa9'
    b'\xc4@\x9b\xe4\xd9\xe9c\x11\x1e<\xb9\xf4H\xd9,&\x0b&\xacN(Dg\x91\x16,\x9az'
    b'\xf5\xbc\xef\x94\x81\x98u\x04\xe4|e\x94\x0f\x96\xf9\xc4=\tO\xc2\x01\xeeF@'
    b'l\x10\x02\xa7\xfb\xd2\xe2I\x0c\xba&\xb4\xe0:\xd3\x9a\xe9\xff|\x99Q\xdaM3=,M~'
    b'\xa8IO=\x7f\x01\x08W\x95\x9c\xa4K\xfc/s\x13~e\xf6\xb5\xd4\xbfw\xbfI \xfc\x9d'
    b'\xcbT}4\x92\x15gX\x044Zk\x10\xc3\xbeu\xe6\xf6.Yj\xf4\x1a/\xb1\xa9\xfd\xa3'
    b'\xea\xfcF\xc9\x0e\xbd%\xb4e\xf2\xee\xb1\xfa\xf2\t7U%N\x04V\xf3Z\xdd'
    b"\xa1\xf8\x05=\xda\x14\xa8\x19N'\x97\xc4K \x7f\xb0F\x8c'|\x12f\xccX"
    b'\xbb\xee\x1d\x83\xdbu<\xf0C@\xe1A\xbb\xf6q`\xe0\xff\x8b\xbd\xf6M1Q\x12#\xd9;'
    b'Y\xc6\x9f#[l\xbew\xc2\x80:\xa6\x88\x08\xfa\x04\xa6,]\xcf\xa1\xc0J\xe4\xf4o2a'
    b'\x1b\xe1R\x01h8+\xeb\xf6p\xe8\xd0E\x05\xc9w&^0\tx\xff~\xab\x98\xf0\x85u'
    b'u\xd9\x89\xb4\xf6\x8e\xa7\\\xde\xdb$\xec\x14i[\x88\x06Qt\xc6\x00\x1e\x99\xe1'
    b"_c\x14\x00\x81\xc2.\x9d\x8b\x98'0\xaed\xa7~]{I\x02\x11\xab\xb1\x1a/\xafc\x03"
    b'\xe1\xb0}\xf1y\xa4\x1dcg\xd3\xacsi\x99\xf1<K\xbc\xd3p)Bz\xd8s\xe1\x01\xfd'
    b'\xc0nH\xb7\xa0\x7f\x7fC`%\xd5\xb5A\x9b\x13\xd1m\xa3\x98\x7f\xc6\x1ab\xa5'
    b'0\xc1\xe4)\xeb\x1a\x96\x8c\xf7\xf1\xd3\x15\x87<\xab\x1b\x10\x82\x1e\x04'
    b'M\xc1\xe2<\xea\xbb\\\xef\xe5*\n/P\xb1\xa4x\x1a\xad\x19\x87\xbf\xe4\xf9q'
    b'E\xf5&\x1b\x11\xa1\xe8\xf8\xdb<\x9fG~\x99z\xcaB\x1fU\xb0\xc2GR\xdf'
    b'(\x16\x9a\x10\xdcz\xe2\x990\x14\xaf\x1e\xf7\xc8jk\xd8\xba\x96\x86Vv?\xdb'
    b'i?\xbb\xb1\x83\x06\xf3\x82\xbb\xb8\xb7"\x9b\xde\x8b\xf7y\x1b\xfb\xf6'
    b'\xa9::\xf2\xbe\x7f=\xf6h\x975\x99\xee\x81\xaa\x0e\x1a\xc2\xd1\xdd\xabD0~'
    b'\xa0[A\xb0$\x8e\x88\xf0\x8a\x97\x19(\x07o5\x8a\xaa\xaf\xe77\x05|Du'
    b'A\xb4\x94\xb1\xbd!F8w]r\xcf&\xea\xe5.\xbd\x97j\xa5\xad}\x13\xcc;\x19\xd2\x1f'
    b'\x1e\t/u;<\xee\xcd\x9e\xa0\xd7\xd6\x98\x97\xe7.\x17\x1b\xe0\x0c\xc3M\xff.'
    b'\xb7\x84\x0c,~\x96\x13\xad\xc2\xee\xe1dlq\xf8z$\xd8H\xd0\xa0\xbeQ\xc8'
    b'\xca`D\xff}K\xad*\xa6\x98o\r(\xa425\xb1ac\x05\x88\xc0%\xd5\xa9;\x10I'
    b'\xb7\xcf\xae\x97\x85\x95\xf8\x1e\xd1\x91\xfbzU\x05\x95t\xbf\xfc8\xad'
    b'\x9b3\xe3\xa1\xe4Z~5C\xd2f\x83\x8cD\xea\x07,q`{=\xd7\xeb6\xe8\x81\xaa\xb6'
    b'\xd03\xa7\xcc\xc3\xb6h\xe9j\xcc\xcd\x04wJ\xa0\xf1\xc0\xcea#\xddB\xc5>h\xd2v0'
    b'\xaa*\x08i\x00`G\xf0d\x97s\x82\xe0^\xfa\x9eIw\xc4\r5\\*t\xf6fP\xdd'
    b'\xd7j\x86\x03\x18)/\x87\tWVs\x90\xb6\xec\xef\\\xd9\x18\xad]\xc6{\n\x06\x07+-'
    b' $\x16\x1b>\xab\xdb\xa3N_h \xf0u/\xf56a\xa6X\xffG\xb6\x9f\x9a*\xd1\x1c'
    b'!\xeb\x81L\xce\xa8\xdbN\x98\x9bX\x0c\xf40MG\\w\r\xf9\x10Z~\xb3\xd8or\x8e'
    b'\xd6\xe9\x92\x95\xcd_\xbf\x9f\xcahA\xaf\xc9\xd2\xc4LS\x80\x0bW\x95Hv\x9d')

test_signature_Stake = (
    b'\x00\x00\x00\nqv\xfaUe\xc5\x9a\x87uz\xc3\xa3\xc4^D\x84z\xd2\x98\xce'
    b'"(\x08\x9a\x1c\x9e\x0b"\xc5@\x9e\xc2\xb2\xb5\xf1\xf7{\xf92\'\xbb\xdb\np'
    b'\x10\x11\xbb\xa0\xef\x18K\xc1\x16\x88\xed\xae\x88\x90\xe6\xfb\x8e=\xdbw'
    b'\xc2\x82\x83_\xc6\t`\xa6\x07\xdb\xfd\x00W\xcb\x83\xec\xec_]\x92'
    b'\x17\x90\x85\x07\xbf3(\x7f#\x14w\xb9\x01>X(\x11\xd41\t\xd2X\x0e\xca/4\xe3c'
    b'\x99q\x1f0\xb5\xf1D\xd2\x80&\x95Z.[\x08K\xff\xb4\xf6U\x06@\xb0\xf6'
    b'v\xfd\x80\xd4+\xd5\xd3\xc8\xeeP\xe9 !\xe4\x85\x03,\x1c0\xd2i?Y\xd9'
    b'\xb4\x14\xfd\xe0aL\xf0\xf8\x1c\xb3\xaa\xe4\x89\xa1\xc0\xf3\xa6#\x1a\xb0'
    b'W)\xfcB\x1d#\xb9jvJ\xee\xd2\xc7:7N\x9cy\x923\x9e\xbc2r \xd1\xb8U'
    b'\xe9\x17\xf5\xecV\xbe\xd4\t\xa7\xe3\x01\xc5\\S\x1d\x89j\x83\xeb\xca'
    b'\xf1A\x88F\xab?\xad\xb7\x1c9\xa2M\x18\xbb\xf7\xb6J\xfaq\xf0\xa8\xf1\t\xfb'
    b'\xed\xf7\x02\xfe\xe7KQ\xd1}\xd6\x82\x14\x90\xf1P\xdd\xc4\x1a\xbe\t\xcdQF\xb9'
    b'H\x0e\xcbG\xca\xb9FV=?)j\x93\xce\xb8\xc8\xeeN\xe8\xd8\x04\xa6\x11)'
    b'\x16\xa0\xbe\x0c\xd1,:@\xe4`\x0e/L\x0b\x01\xe8\xbe*7\xf1@C\\}\x9aQ\xbe\x98'
    b'\n\xa3\xeb\x1ce\xc5+\xfed\n\xed\xa4\xf6DTQ\x9f\xcc(\xa9\xaf\xcb\x98\x8a'
    b'i3\xdf}\xc7,c\x14N(\xf6!\xc7\xbd\xe1\x87bF\xa4\xa9x\xe0\x80\xbf\x03\xdeyq'
    b'\x10\xfa&\xde\x81\x17\xc5U)O\t!tZ\x8b\x0c\x9dyz\x98D\x85-\xea5^{\x0e'
    b"J\x98\xd8P\x9b)\xcf_\xbeQ\x8b!\x03)\xe8\xc9\x15A\xe7'\x0c\xfd\x1d\x85"
    b' \x0b\xe3m\xdd|\xa7\xa31\xce-\xc6\xcc\xec\x1a\xd5\x96\xf1>C\xb2y\xaf\x18'
    b'\x02\x92\'\xb0\x8bn\x94fW\x8e\xc4\xe1\'\xd3\xc1Q\x1b"J\xce\xf9\x13Xl'
    b'\xdcN_\xd2\x12\xa9\x19C\x8d\x06X\xd4\x14h\xcb\xe6\xf0-\x8e`\xf1\xd5$#'
    b'\x9f|\x8c\x1b\xca\x9a\xadb\x1cu.+N\xc0qqlMHY\xcet\x86\xfa\xdf\x89\xcd\x00'
    b'(\x9b;\xa8_\xa8\x9f\xaf\x9fd*\xe3hc\x99J\xaa\xa8R\x80d\x8fOu>\x05-\xdb'
    b'\xc4\x84\x9c:\xfc3\x1e\xc2\xaf\xf8\xc3\x98%\xa1\xffqe\xb4\xc3G'
    b'\x9d\xa9\xee\xadOM\xfbV\xa7`\x12\xd0\xe1\x9d\x0e\xb3J7\x19\xbe\t\xbe\x9a\xa5'
    b'G%\x1d\xc1%:\xa5|7\x9c\x1e\xa04\x06\xd9\xe8`\x82\xe3u\x86Ve\x9d\x159\x03\xbd'
    b'\xfd>.\xaf\x8f\xd0\xe8w\xf7\xea\x12\x9dI\x93\xa8\xc7\xb95\xea\rQ\xbf\x8a\xb7'
    b'\xf0O\xa6_"\xd5\xe9\x03=\xf8\xa8\x84\n\xdb\x97\xa5\x91\x1d\xbe\xac'
    b'\xcd\xa2\x8e[\xb8\xef\x84\x96\xfe\r\x7f\xcf\xb0\xf37\x18\xc9\x9e\xdd['
    b'\x92#\x97\xae\xde\xaea\xe4i\xd3\x07I\x1c^\x13W\t\xd0\xcb$[\xb2\xa5_'
    b'\x08g\xad\xd5\x15\xffL\xfd5!Y\x15\xa1\xab\xa3c\x10\xd0_`\x97\x8af\xf9'
    b'\x05g\xa3nF\x02V@\xd3\xeaM\x0eK\xe7\xf1nI\xa2\xcfB\xea\x84\x8d\xb7q\xac\r\\'
    b'\xf3%i\xb0\xd0i\x17\x8d~\x93\xcb%\xe4\x08\x01\xfa\xf8\xedH\xe2%\xd63\x97'
    b'\x15\xf3\xae\x10\xb950\xe6\x88\xe7\x19\x9eL\x1c%\x96\xe5\t,\xdev\x9a6\xd7'
    b'\x8b\xb5]\xbd\x9c\xa07>e5\xdd\x04\xf0\xd5\xe90m*"\x86B\xc7\xff\x9f'
    b'\x07\xd8\xbd\x84\xf7\x0b]\x91\xbe \x94\x11:\xbc\xd6.,\xce\xdbo\xad\xd4J\xdc'
    b'\xd7;b\xc8\xe8\x8a=A\xc5)\xabpC\x00c\x8e\xccz\x806\xd5`\x05~\x81\x174*'
    b',!\xdc\xfa`=T\x8d\xe6s\x00n\xca\xc1v\xe4\xcf\x97Z\rh\x12:,3N\xc6E\xd37\x1e['
    b'\xc40u\xa4T\xa2\xf01\x96\xbb\xfc\xd8\xeaTq\xd3o\xf1\xa8\x9d1\xf6Z\xee'
    b'\xeb7\x85\xc0\x84\x88\xd8\x1c\x8di[\xedr\xc5\x8f\x0fpWQ:\xc7\x14L\x8e'
    b'\x15S\xa3$\xe8*\xb4\xa2\x83\xdf-\x8f\xc07\xb8[!\xdb3sW\xc7\xdeMF\xf7\x8e1'
    b'@\x95\x06\xeb>H\xa8\xc7\xaa\xcf[\xd7QCj#\xb2\xae\xc3t\xda\xc9T\xe7'
    b'\x10\x8a\x9bEB\x15\x81\xf8\x06[G\x0b\x1e\x80\xf2\x91\x93q\xc7\xd7\xb1X\x03;'
    b'\x1fY\xf5\x10A\xbf\x03:\xd3\xc5\x98jU\xcao\x98\x84\xcd\xc8\x9fm-|\x93'
    b't\x18I\xaaR\xa9\xba!V\x1a_\x01E\xe1\xdb\xce\x9a\xb0u\xae\x9dL\x88\x9a8\x14X+'
    b'\xa8\xd0+\x1c\x06\x8dX\xd7\x99:\xe9]K\xfd\xba\x88\xcb\x1crIQ\x8b\xddb'
    b'O\xc9\r\xbd\xa7\x01\x00\xd6\xe3\x8f\x06\\f\t\xa0\x184\x05\xb8\x10'
    b'\x0b\x19f\xd5\xc6\xc4\xcc\x8ct\xde\x89~\x9d\x8e:\x8c\xc6\x08\xb40'
    b"v\xb4\xed\x89\x97\xae\xf5\x99\xf1\x8af'\xcbc\xd6\x1d\txe.\xb9\xbf\x04C"
    b'\x16\xe1\xedA\x14]\r\xa7\xd5,\xd5#\xb8x\x07\xbcex\xbaIi\x00m\xc1'
    b'\xd6&\x89\x0b\n,\xb7\x95\x8c\xc9\x08?\xbe\xd3\x81\x10\xc6Uu\xab'
    b'\xcf\x83\xc2\xce!S\x8d\xb7\xa7\xc5\x88Y\xe9\xa3\x96\x82\x91\xc2D\xf7'
    b'\xaa0\xa2\xde\x08\xb43\x06\xd7\xd4\xf4\xfa\xb3GX9\x94\xcc\xfd\x9bi\xb7L*'
    b'\r;7\xef\xc3g\x9fD\xe2\xb1\xf8\xbb#\xfa\r!8\xc5=(\x06\xbf\xb3\xbc'
    b'\x99\x9b\xa9\xba\x99\x0b\x96\xedAa\x01\x8bN\x01\xa6I\xa5D\xadc}\t\xf3E'
    b'wo1\xb4sc\xea\xff\xa1\xfb\xd9{myP\\\xe2q"\xd0~]\\BX\x99\x15\xc6\xb6\xbd\xd5*'
    b'\xde\x04K\x85W\xf0Ht\x00\x1d\x0b\xd5U*\xdc\xd6\xcd\x05\x1c\xe6\x82\\\xebc'
    b'A\xd7\xc82x\x00i\n\x04Dd\xb0\xfa+\xc7}\x87bP\xe0\x1a\xd3?p\xedA\xd0\x86'
    b'b\xff\xbd\x1as\xde\xb0"\x1e`o\xdd\xeb,km\xfe$\xf5\x07\xee\xd9\xde\x8c'
    b'S8\xef\xdd\xae\xac\x1c\x93\xe8\xed3\xfd\x19<#\xba0\x1d1%\xf7x\xfbn'
    b'\xd14\xc8\xd6n\xea\xb4\x1f\x80\xc8\xb8\xc1E\xfcx3\x81Z\xdfo\xbc+\\\xb7'
    b'\xf7\x01\xc8\xac\xb3\x0b\xf9\xab\n\xc7\t\x9d\xe6\xdd<\xe4\x9f1\x88V'
    b'}\xc1\xe7\x19E\x15\xdfv\xae\xd1R\xb5\xc0\x82\xd0\xa8\xd5\x86q\xed'
    b"\xbb@\xf3\x1b\xccH\xc1\xf7\xe8\x1c^\x9aJ\x05\xe8\x83|\xba'/H\x95Y/"
    b'\xd7\x12\xa4\xa8\xb8S\xadB\x83X\x0f\xdf\xf2d\xe9\xe9\xe2\xa8%#\xb2\xe9n\x82'
    b"\xa1\n\xc4#\xd9-_\xce\xbd[Vkh\xd0\xc7\x8ah\xae6\xd1\x8f\xb6\xd4'\xc2L\xad4"
    b'-yA)\xf7Z~\xef\xa9\\\xa3\rr\xfeb\xfc\xdc\xc4\x01\x03\x155\x9a)E\xe4\x9cQ'
    b'x\xaa\x97\xe9\xe0\xb3\rw\xa3\xca\xd4\x05[\xb7u\x80\xcbT\x11H[\xd2T\xee'
    b'\xab\x03\xd1\xbe\xc9~\x88%AaU\x8b\xe4\xa4^3\xb5\xb3\xb1NT\xc9\x0e:'
    b'\xcf\x9a\x18\xed\xdd\xb2\xeb\x9a\xa4]a\xefq\xe01\x8f\x1e\x89h\xb2'
    b'\xf7f\x85\x1d"\x9a\x1e\xdb\xcd\xb4)\x82\x12\x8a\xc5\xebE\xfc\xdc\x1d'
    b"\xfd\x0eW\xf9\xda\xda%\x07\xfb\x93\x80\xc8\x16\x1a\x96'47o\x99\x1c\x9aF\xcf"
    b'\':\xb3\xbe\x90"\xca8+\x9b(\xc0\x1e*\xa1\x19\'P\x80FR\x8b\xddGG\xcf\x8b\xcc'
    b'\x11\xe2\xdd\x0f\x868|\x8d\xf0\xa7\xc6\xce\x0fpop\x91\x97\x1d6\xe5\xd5I\xa7'
    b')\x16\xb9"l\xc1q\x9eDM\xeex\xeb\x16\x05%3\xb5\xa2%C\xadW\x94\xaf\x91P\xf8'
    b'\xa7\x8fd\xe6\xc6\x1ab\xa50\xc1\xe4)\xeb\x1a\x96\x8c\xf7\xf1\xd3\x15'
    b'\x87<\xab\x1b\x10\x82\x1e\x04M\xc1\xe2<\xea\xbb\\\xefCC\x14x\x95\xf04\xd5'
    b'\xfb\\"V\xa7\xa5Q\xed\xf1\x99\xf5\x9cC\xa6\xa0o\x95K\x98sg>\xd6\xcd5{j\xad'
    b'\x8b\xd0\x90k\x98\x07\xde\x17\x00L\xf2Yl\x03\xbe\x96\x00\xf3\x07B'
    b'\xc3\x88T\x0f\xe5^\x88\xc3i?\xbb\xb1\x83\x06\xf3\x82\xbb\xb8\xb7"'
    b'\x9b\xde\x8b\xf7y\x1b\xfb\xf6\xa9::\xf2\xbe\x7f=\xf6h\x975\x99U\\\xbae'
    b's0\xe8g\xd2\xbed\xebz0\x8f\xda\x19\x81\xfc|\x0e\x11\x81C[\x9fn\x07\xcf2.\xcf'
    b'A\xf5C*\xeay\xfdu*\xac\xceU\x96(*\x1f"\x95\x12|m\x19r\x10)\xa0\n\xbe'
    b'\x05\xac\x84N\xccu\xa1\xae\xe8\xfa2:\x87{\x7f\x90\xce\xe8lk\xb9\x06\xa0\xca'
    b'\x9a\xd33\x19/\x86X\xf9\x81\x99\xe4\xccg\x80\x87\xe3`]wrHH\x1b\xb5LN\xc4S'
    b'\xa6\x8dt\xa0\x96\x98\xc4\xee\x9b\x8f\x87\xa55\x8d\xa9\xbdf\x13A\xa0'
    b'r\xaf\x8c\xbfoY\x95\x92\xcb\x19\x12Yy\x90\xe3#X\x86T\xf3h\x08\x02x'
    b'\xb3\x15\x9ba\xa5\x0c\xa7P\xed\xfe\xc9\x0e\x13\x12g\xa7azgY\x882\xda\xb5'
    b'\x90b\x16\xe6\xedR,\xfaM\xd8\xad\x8d%nX\xa9\xcb\x11,q\x986IT\xfc\x90\xac\xc8'
    b'E\xf5$\x16\x0f\x17\x82x9:\x8a\xa3hP?\x19d\x97s\x82\xe0^\xfa\x9eIw\xc4\r5\\*t'
    b'\xf6fP\xdd\xd7j\x86\x03\x18)/\x87\tWVs\x90\xb6\xec\xef\\\xd9\x18\xad]\xc6{\n'
    b'\x06\x07+- $\x16\x1b>\xab\xdb\xa3N_h \xf0u/\xf56a\xa6X\xffG\xb6\x9f'
    b'\x9a*\xd1\x1c!\xeb\x81L\xce\xa8\xdbN\x98\x9bX\x0c\xf40MG\\w\r\xf9\x10Z~\xb3'
    b'\xd8or\x8e\xd6\xe9\x92\x95\xcd_\xbf\x9f\xcahA\xaf\xc9\xd2\xc4LS\x80\x0bW'
    b'\x95Hv\x9d')

test_signature_CoinBase = "0000000b01c683d859b4f21c43e0564be6b9580356fd983f5ab2e25ec51573c2" \
                          "fb2bd5939854e491fcab92749536cc36f73cd3fa1752b3a9c48c3507dd3091a6" \
                          "a4de2b73a385daa234fd9ed432349ce94a491ce1954062b7e3fb96c2677d9e4a" \
                          "51d3dc92165c4804f9f32041c944b032a62db32d2aa108629699abde6a9346fd" \
                          "f253617d44a52b39082730bc8ecd07b5bba2a986f9339107849d8df2b38d880f" \
                          "2bd63b7b38e16d9e2a1950342dc96d4d5e2ceb32f25fdf34d93253bccd9d8dd5" \
                          "25b3a49d5833c6b521396848af2e38f7d573cb221f25448605e949ef50846083" \
                          "44b85c4e1bb2e4af05a265dd1094bdaba8e5c89352863a7cfb38a77c993ca4c0" \
                          "52226f5001e3bcdbc4a21ed9cc5c1817598255f8076762d29ea764a0b9204467" \
                          "abebf07c79938824e9fd038f998ccd1b6471a7d3b134a24a273fcd386ee0f181" \
                          "be8d1550fec060862405d2df920fd05b92905032111055deb564d3e5ae2ef79f" \
                          "2d126ab505f9053bdd7fc2d23eafdab0cb279891d4443f3857cbb09e2a3b40f3" \
                          "0a60d50a6a66da63a89deeda08ec20075c5649383587a72e3f0293605c100a6e" \
                          "9d72c15e45e6487a8d1d4b5e7132c65297df6dfcf884202de2c8cf4fb813e333" \
                          "45dae7fac0e7fdb12bfd5f2cbc52b85178896bc0977fb0dc62aee0d8427b9c4b" \
                          "cbbfc783b3ffd57317c6b9d6b88f51bc448d7378079b31bffb12684d19ee13bd" \
                          "2f2ee0012820297846285ad4d6c681277af2d34ff5554fa1466d0aec56aed14f" \
                          "ebd532f90fb3599ba34bea97576aea83a24917549ce00a22b908b7c38f050add" \
                          "76a562e6d0004b6a9ee9d71ac5ee6ab808be180c2dab3b9085f53103196a69ce" \
                          "b544e05802d4398dbc8a38b1bef383b3373d4b4d49830e10dc404c9b1f78c23b" \
                          "18fd2d9a05eeae620a4d5e4103c879f40e49f5b4b8fa1f12b6184ddcbda59af9" \
                          "300ac0492e582989b117a5cfc815d7e2f035ff1039236f1124aa389df44ba6e3" \
                          "3c846221d09ca056779003461716399826f79d3dcd60af51e6a44b1f03ddeaab" \
                          "dcd5e286d3f6b131c680e6237c264887d4909b62a3b43cdb6e682bbdda34c445" \
                          "e3e734617a2e5f64dd29d970154f568da88e18d388671be52fcfe1e7aa547caa" \
                          "e294cc10ad31f5ff31e0b87dbcc7a756063dd4faa26713575d9d3fe53851289e" \
                          "c82c852a9c0978ab2de177b0f482d8be9f2e2d6bcb01109e0fcc8a79028b6520" \
                          "a677d1c30eecf450f5de585793e69fddc495c143e8833a169b412f5e24f1c8bb" \
                          "bc328e134051667bd68786cbba7fd62890d33c574d5f5f9dc49316490bfa6241" \
                          "eac7e2fa5c3a6b5648dfae101b6afb7b587385222a85882e6702b77fae000400" \
                          "3576768d290095658e3c31e8584ba47c84c39efe17b8e0c099b3aaa4e48f5ec1" \
                          "92c1a407b6196b95ac269b6e544ebec15da1e5518a72917c1f1ea6fa0d860a12" \
                          "070f2126cece072a9ff74ef3c4137dd17011112eb174438956feae15cfefa2ce" \
                          "28203a7784d8ce2c24136b54b3ac5092fcb906e4e56a05024b2b0480d2994446" \
                          "93b0ff7b1c056bed6a3f517d6bd9844a9a63df53511b918761c8f2825f01232c" \
                          "d6a9e901a88dab50381bf7f455fc7fb5ec10f5c4cfa57a648290615e04a12e28" \
                          "57047b4576175c97982171f78f0a90b795a4339ce485561cbe38294bb124b88e" \
                          "55b397218170e6eee2d3447a750a6285d337d261765d0bd19c6ead89acf8940a" \
                          "d339c115071c84314457f9420dd280b6b55dc50d0e5cf1c1007d2001dcffee74" \
                          "6bd93525bd7363e70836e310a79e705f56022e8b56391ab62db863b7a8158b5d" \
                          "d6efbb22d15c146af8b07a9e37409cbe3f8de08904da7ae22412f6b564bd07b7" \
                          "a8e99ce964f86b513ea1b6925615e0ffcb811a4ea92013f3f5771208131bc507" \
                          "bc587f9b743f93a581cbed16c0b2f9ff48d7368954cdf997673dc7db1cf58170" \
                          "a90f4080c7ef753495ea0fe34e5d85c26bf1305aa032c3aa4f5fcb909c558089" \
                          "1e1a82613aeae4b171448ec4b2ec31d0bc84e5fe4d5629bc85d5699e9c488d7d" \
                          "f7fa35feade75790b751556198da14ce0ac92d39d9e0ee6d0f6f94803556587e" \
                          "2c53612a68639f944157feb39fa5495ad576d93503d30022d142ae5c77c2495f" \
                          "b5b1253aca132d0da6393e254a04da0e8a8edf9ecdc1bf8d59d0676d0fd408aa" \
                          "38297d0eb3a9e6c41660188be9e1e5575063ef5b5c7a491cd4331d3042375fa4" \
                          "d1f6145717a2ec0fe1d3372404710bf4f8b3fc931d7cc54ee0be529c0c2bacd2" \
                          "923cbff45b080eade590a2506549f7e6ada2361fa267fdacb3035a4456bbcc72" \
                          "c89396db3ec45cf609da798358a00a9c98ac06a7ae3e05eb526b3798be3481e0" \
                          "a5212e7385c790bffbbf3ed963c918811f342b51790951472f7cfd2fa05c9845" \
                          "0a3a76e5182f132c90721948d5520ed2a73c1ea651075e994c06f13348339f4a" \
                          "12f3b16f19193e8b4004a7b660d3e3f604809a459421357c70c73d327fcf145d" \
                          "adfe753050186c07f3d7aeae8734ccd1e1f4106830c9ddb95ea69c49dfd893d8" \
                          "12e42872de11d90da086a8f457c5fa3ba5b4bd4e0d6d7c21e55df9741e3632af" \
                          "1a6fbd7ef13fac16f813e7c753b6b583c063d1c3a34b777739758efa9a540d97" \
                          "26922a9c388c882bea70d6d3b6202b43fc08fd49877cc7c635cc0cec3cd6c7f3" \
                          "e6a6903f10531280e39e3750e69ba68fdc96f23af859798be76e66349b88bcdb" \
                          "5b359f3f9f3ed121292d7020dfed018c1c211f54434810f3e45c87ca09995ec9" \
                          "6257aea6f8736077c2c35416973ac7569c413c962ed85f99d811373827595f24" \
                          "06de1b7124d0c086a224b1b0efd06e24aeec419b700e0eb498c41b63a31e49a8" \
                          "a36cd784d6863be73927127a4aa629e29b8a141a214f07a91341d533d4d4c6e7" \
                          "b6bae76344fa39e7bab289c54995f904dc7fb27e79a4630aaf1698b8640bec7f" \
                          "b5f216509c7249b88b74a44091fcd5223c26635773a77bf83ba5a08fdab4af69" \
                          "e21d705025ff166fa452642a1e4babbf8b188422ce75389b6335091204f0f03d" \
                          "78a5010e24221e5b212e67d0af41a706e59e3608b52917bcc0bf8b2990f20799" \
                          "e24fd62002a5287e14dff7ad53c21e16b62a15b2955584682c2aacf784908653" \
                          "f731168d90b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                          "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                          "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                          "9548769d"

test_signature_Vote = (
    b'\x00\x00\x00\x0b\x01\xc6\x83\xd8Y\xb4\xf2\x1cC\xe0VK\xe6\xb9X\x03V\xfd\x98?'
    b'Z\xb2\xe2^\xc5\x15s\xc2\xfb+\xd5\x93Y\x1d\x92eot\xd9E4\x7f$B\xe6p\xaa\xed'
    b'/w\xd2\x96\x12+\x0c\x87\xbd\xbc)\xa1Y\xf2u\x99\x07\x08\x0es?\x99\x10\x94'
    b'\x13\x81\x1d\x18\xd1\x99\x9a\xbb~k3_\xbei{\xd6\xad\xe0\xb2HK\xf0\xed@'
    b'\xfd\xfeNU\x83o\xc8\x81\xc3\xa7\xd6\xb1\x8bye<\xdf"\x19ZEk;\xeb'
    b'\xb0\xc1\xae\xb6FQ5\xe98\ro\xa8\xd4IG;gA\x00\x87\x8f\x99\xb9\xb8i1\xdfo'
    b'\x91\xd5\xcb\xef\x8c\xe2\xd3\xf2\xa6Q!\xb7<j\xa7\x01\xf3\x91s\xb4\t\xb7TD'
    b'\xb0V\x85\xdf\xf1\x9c\x13O\x1eW\x17X!_+\x90y%t\xceQ"9>\x0b\xfd\x85u'
    b'\xa4\x18\xa0\x8c\x12\x05\xacX/\xec\xcf\xb74W(\x8c\x97\xb9\xb7\x91'
    b'\x9b\xed\xfe\x1e\t\x9a\x8bFW\xaa\xbdN\x9a?\x06\x91\xf6\x16\xb2\xbe\xa7As\xd8'
    b'Vgj\x96\x03\xab\xf8{\xde\xb6b\x837\x90\x8e\xbf>\xd1\x8b \xa0\x9a\xb3\xd7'
    b'\xb9\x10$8\xa8B\x934\xf9\xa1\x15"\x84\\\x1e\xa4>\xe0\xea\x96\x93X\xea8'
    b'\xe1e\xd6\x97\x1e2M\x02\xf5\x15\x9a\xb5h\x1f\x83\x16;\xa0&\x8b\xc2\xfeB\xcb'
    b":\xdd\xf9<\xef#\xb0\xb0\xcb*J'\xea\xbf4\x0eQ\xe62C\xe49:\x0b\x9fJ\x14\x91"
    b'+\xc6\x964\x8c\x18"@oz!I\xac\xf4\xb8\x0eh\x87\xdc&^I.\x1b\xb0\x02M,'
    b'w\x8b\xb3\x9a2e\xc7\x99\xa2,`g \xd5a\x07\xe4\xcbY\x00K\xc7\x0c\xf0'
    b'\xa5\x1dU\xfaO\xb4A\xae\x04z\xca\x0c\xff\xdd\xf7\xa7\x81B0\xe7\xc3a|l'
    b'\x7f\x8e \x1a\xf4j\x89\x15)\xd7\x0e\xa9\x87\x16u#Gj\xbd\x17\\\xdc\xff1'
    b"\xc5\xc7?'\xd6\x934<\xf1\x1c\xbaC}L\x92\xf6\x07\xf3\xeb\xe0a\xab\x87\xc1"
    b'\xdf \xdcP`FA|\x93\xe7F\x9f\xf5\x9e\xeb\x88\xceJ\xdb\xedk\x1f\xafa'
    b'\x81\xc6;\xfc\xa6\xd8\xeb%\x84\x90\x82\xec\x8a\x15\x0e\x94\xaf\xf7\xf9\xc8'
    b'}\xacX\xb9\xa5\xc2\xb6>0A\x17\xfds\xda\x10\x8d\xd9\xa9~s\x17\xab|\x81'
    b'M\x14\xbaJ;\x92\xf1\xa2\xbf\x17\x0e\xb1\r\xde\xff\xf6\xa8SW\xf0\x93\xe3B\x17'
    b'\xcc\xedh\xa4\x99\x94\x87\xde\xea\x85\\\xb2=\xb0((\xd0\x00Kj\x9e\xe9\xd7\x1a'
    b'\xc5\xeej\xb8\x08\xbe\x18\x0c-\xab;\x90\x85\xf51\x03\x19ji\xce\xb5D\xe0X'
    b'\x02\xd49\x8d\xbc\x8a8\xb1\xbe\xf3\x83\xb37=KMI\x83\x0e\x10\xdc@L\x9b'
    b'\x1fx\xc2;\x18\xfd-\x9aK\xd9\x88\xe2\x14\x04t~}^\x00\x8f1\xe7\xc2\x84'
    b'|>\x99\xd4b\x91\x02\x8c\xafeI\xb2a\xe0\xac\xb5|2y:&\x86#\xe7\xc9\x86}"'
    b'\x07\xda\xbb\x99p\x87d\nR\x12\x95JQ\xa3\xe1j\xf9\x843m\x1e\xc07\xd4'
    b'\xf0+b\x82\x96h\x9cOY\xad\xce\x93\x94<q{T\x00\x7f\xe1\xbf<\xe9\xdb'
    b'\xda\xeeo\xca3\xec\xcb\xe6n\x9b\x08\xf7*\xb8akn\\\xdel\xa5\x10\xdd\x14'
    b'N\xc9\xbe\x96\xe0Ki\xa0\xc1\xd0\x91\x89\xd74\xf8\x887\x04g\xfbJ\x01"\x84'
    b'\x1bXB$\xd3L\x08\x90\x96?\xe6\xc8\x1e\xc3\x84=\x13\x83\x89e\x03\x0b[\x96'
    b"\x91D\xd5|\xe1?\x06\xe9\x1f!\xa1\xadR\xe7\x9e.'\x8c\xe6\xbb>\x0bU'X\xf2T\x04"
    b'\xf1qh\xdf\x1a<\x0cJ7\xcc#\xb3H\xb2\x8b\xa1\xabi\x07\xc5\xb7j\xe6\x88'
    b'\xdaN7\x8a\xf97)\xac\x1asY_\xb2\x81V\x88\x1b\x05\xa8\xf6\x14\x9e\x13e'
    b'k\x1b\x1f\xc1\xae?xn\xc1\xae\xa1FL\x96\x92\x02^\x97\x8b\x10\xddE\x87\xd0'
    b'\x98r\xc5\xf1+\x82A\x9djW\x84\xcd\x02o\x88\xae,+\x7f\xbb-\x8e\x91\x89\\:kV'
    b'H\xdf\xae\x10\x1bj\xfb{Xs\x85"*\x85\x88.g\x02\xb7\x7f\xae\x00\x04\x005vv\x8d'
    b'\xd5\xa6\xa1\xf8\xef\x19\xe31\xb1]\xb7\x8d\x98\x0c\x9e\xeaH\xf6%\xa3'
    b'\xa4G6\x1d\x1f(\xe8,L\x88\x95v\xb6\x19k\x95\xac&\x9bnTN\xbe\xc1]\xa1\xe5Q'
    b'\x8ar\x91|\x1f\x1e\xa6\xfa\r\x86\n\x12\x07\x0f!&;\x08t>\x182\x8b\xb2'
    b'\xdf-\x89JvqA\nrY?\xb2\x80?\xb2{p\x0f\xa2^\xa0\xc9E\xa9\xf3\x96\xb1#'
    b'f\xcb\xc8\xacA\x99\x04Ez~y\xa1\x17I\x9e\xb1\x0c\x87x"I\xe2!\x97'
    b'\n\xf4\xd8\xbf\t-\xb3\xb8\x05\xa2\x9d\x8bOkw\xf8\x83Z\x15#\xb2J@\x9e'
    b'Q\x13\x98\xa4\x0b\xd9\xf1}\xb4\xee&\x8b/\xf7\xbcBox\x9f\xad\xa8\xd1\xf5\xc4'
    b'\xfbEy\xb0\xea\x02\x90D\xa4\xd8\xcb\xd9\xf81\xcd#\x15\xf4}\xdf'
    b'\x14\xf8\x83\x8d\xbb\x19\xe8\xb4?&\xe5|\xd8XX#\x0c\xc2\x8f\n\xaf\t3\xc6'
    b'\x16\xa0\xc5\xfa\x96e\xf3\xcf\xae3xe\x11\xb3\xf4.bR\xe4\x1a\xda$\xe8\x8f'
    b'\xd8\xbc\xf6\x06\x813=E\x82?\xf5\xf8c1\xea6\x9c\xc6a\xe1\xc9\x0b\x88\xff'
    b'\xdb\xb4O\x1cA\x1fM\xc5T\xef\x8b7\xaf\x91\xcd\x84\xab/-\x19\x87?\xff\xa7'
    b'tb\xb5\xd6\x04\xe5\xbf^\xe2\x042\x8eLL<\xc8\x9e\\\x1a\x06\x1f\xecw\xf7\tZ}5'
    b'\x8e\xe2=s8\xac}\xab\x84\x027Y\xef\nDU\xc7\xa2\xc3\xad\xa9Q\x91\xf7&T:\x86'
    b'\x0f\xbf\xfeN\xddi\xaed\xfe\xf7\xb3+\xc7O\xc2\x16S\xaa@\xa1\x87\xa8\xf0N'
    b'\xdd\xcat]\xf1\xaf\xee\x1cS\xb2+\xd7\x7f\x89\x8e\x9b\xe9sN\xae\xa93)+'
    b'\x04\x94\x06\x96\t?5\x97\xfa\x00}\xba\xb97&a\x17*\x0b\xb4\xd3\xb6\xc5{'
    b'<\xe2Omc\xa3c\xd9iVn\x1b<@\xb0B|\x94\x97|\xb4,\nM\xd6v\x06\xeb'
    b'\x91\xb7\xb0\xe4\xa8\xd3\xcb6\x00\xe3\x1f;G\xe5h\xf8\xaap\xfd\x12\x19t\x81\\'
    b'\xf8\x9d\x9b\xdcE\xa1\xadD\x8d\xbd\x10\x97\xa1\xd6\xb7\xac_\x8d1\x8b5U1-'
    b'\xf7=\x9bv\xed\x84\x9c\x1e\xa5\xa8\x88\xfa\xa1\x16\x8dR\xf3\x19\x95\xd0'
    b'ZZi\x99?\xc6L\xfc\xed\xe5\xf8[|\xf19\x1f\x0bj\xd5\x99\xea\x924\xf2'
    b'\xbd\xa4%\xb1\xc3\x85#\xf1\xe2\xa6\xa4\xdc\xb0\x0c\xcf\xe4h#\x95\xa9'
    b'\xf8\xee\xcb\x0c\x0e\xf6\x86\xff\x94\x18\x8b\n\xe1*\x02XYX\xc7x$/\xc3:'
    b'Q\x99\xb0\xed\x8b\x06\x9e\x0c\x8a\x96\xf9n\x04\x90\xfeV\xdaF\xf4\xfa'
    b'f\xeaY\xb69z\x8e\xc4\xd9AG@4\xa8\x99^\xff\x1f\xd5\x0c\xf8\xc1\x8c\x0c'
    b'\xccv\x19\xff!\xca\xa6;Tx\xf9\x15\xcd)p\x7f\xd3\xec>\xe9\x86\xbc[%'
    b'\x93\x05\x03\xc8\xf8\x0fl\x12\x16\xf2\xe5^Jw\xa6\x97\xc7\x91\xf8\x06'
    b'\xfdQ\xf8\xf61&\x97c\x9f\xc4\xb8\xa7\xee:KE\xff\xd0O7\x19=\xd4\x94u;\x15\xbc'
    b'\xc6aU\x07\xeb\x8b\xb7KD\x8e.(\x05\xde\xf3\xb2*\xa1\xb4\xbd\xcd\xf3y\x0c'
    b'\xe1\xa5\x1ej\x19\xf1\x8c\xb4W\xaef\xe19\xd4\xfew\x8cp\xf6\x05HSO\xde'
    b'\xf5\x15&\xd4\xd8\xb2\xff\x96\xba\xe3\xd7\xa5\xe6\xb1\x8e\xfcr]\x06&'
    b'k\x86\x12\x06.\xb4KT#\n\x83\xa0oB\x8bF2\xe0w\xcf\xb0r\xba\xc3N\x03E\x08'
    b'o\xe41\xd1\nmD\xce\xfdC\x0b\x02cB\xe0\xde\xd0\xed!$\x16\xbd\xc9$H_\x00_'
    b'\xd2\xf8\xd1\xcegQ)\xddV\xeay\xd7\xbe\x7fY\xc5\xb8\x85\xb3\xa2|\x85\x0c\xf8'
    b'\x7f\t\xed\xe6$\x0e\xa5\x84\xa1 \xb74\xc6\xb7\x10\xfe:\xbf@\xc0TBf\x08'
    b'5^\x1b\xcf\xd5b\xe3P0\x80\xdf\xd6P\xd94\xfa\xbc\x0f\xeb\xfd\x99\xf2d\x99'
    b"\xb2`3c-\xe3\xd1\xecY\xa6\x90?\xc2p\x828\x90/\xcaq\xd0\xfe\x8bS'[y\xeb"
    b'\xf2+\xf1\xcb\xa4m(\\\x82mL\xf3\x11m\xe8U\xd7<n!\x0bV\xf4\xa5}\xf9O\x03'
    b'#\xd9\x95\xd7\xba\xf5Hs`\xcd>\x14\xde\xa7V)w\x8b\xc9:\x87\x16\x84{%f\xa6\x8d'
    b'#\xde\xd8\xf2\x1c\xd9\x13)\xef\xa91\xd6\xa7\xb7\xb0\xbaUU\x9c\x00'
    b'u\x98\xf5\x1ak4\xf8\x8d\x87\xed\xa8\xf3\x1c\xc2d\x17\xd6\xd7\x942'
    b'\x13\xfc\x8a\x85\x15,\xf8`\x03\xaa\xd0@\xafs\x82\xfe~f\xba\xa1'
    b'\x1c\xe3\x12\xf6Ln\xa8\x12\x8c\x98I\xe7\x12\x1cA\xca6yo\xbd\xbe\x14\t$'
    b'}\xf8\x85\xde`1\x98\x06\xa8N\xeb\xba\xba\x156zY\xf4\x96\x8e\x91Z\xe3.'
    b'\xa9\xdau\x96k\x07\x17\xcan\xa7\xe3\xe7\x98\xcd\xe5\xfc\xd2\x81\xffb@\xec"N'
    b'*\xe6\xf7\x85\xe5\xeb\xa0\xcb\xf4h:\xea\x9crI\xb8\x8bt\xa4@\x91\xfc\xd5"<&cW'
    b's\xa7{\xf8;\xa5\xa0\x8f\xda\xb4\xafi\xe2\x1dpP%\xff\x16o\xa4Rd*\x1eK\xab\xbf'
    b'\x8b\x18\x84"\xceu8\x9bc5\t\x12\x04\xf0\xf0=x\xa5\x01\x0e\xca\xb1\x0e\x85'
    b'4\xd7\xb6\xd5\x92\x00j\xa8\xebx\xd22\xb8c\xf4\xf9\x9b\x11\x8eE'
    b'\x1d\xbb\xa2\x99\x92\xb4A\xa0\x02\xa5(~\x14\xdf\xf7\xadS\xc2\x1e\x16'
    b'\xb6*\x15\xb2\x95U\x84h,*\xac\xf7\x84\x90\x86S\xf71\x16\x8d\x90\xb6\xec\xef'
    b'\\\xd9\x18\xad]\xc6{\n\x06\x07+- $\x16\x1b>\xab\xdb\xa3N_h \xf0u/\xf56a\xa6X'
    b'\xffG\xb6\x9f\x9a*\xd1\x1c!\xeb\x81L\xce\xa8\xdbN\x98\x9bX\x0c\xf40MG'
    b'\\w\r\xf9\x10Z~\xb3\xd8or\x8e\xd6\xe9\x92\x95\xcd_\xbf\x9f\xcahA\xaf'
    b'\xc9\xd2\xc4LS\x80\x0bW\x95Hv\x9d')

test_signature_Token = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                       "c5409ec2baf0ef36835e9d1f19cfd9268be02af016b2602fc137795b22c68579" \
                       "1991899058feca7f9436abb93715a5abb8f0a4d6b981dd9f4c033d99fc179b8b" \
                       "ddb1ed42762533496a7b8718b7596e472e31670f083b435300569c56366538b3" \
                       "93d6799ea708756d939de29ca1cd978c56aa482909221d0efb5d05d37743d3cc" \
                       "588f1aceeb6e88d51c853b4121d0cd731dfc9211327e78670edeca78173935e3" \
                       "aa1a4171cc2a26ba5de1af5aeabcbac6ab9d16264668658f0958f249c9938e38" \
                       "2cc6600a97c7cc5d8304ae8cae3367452fd68120507ade0e057f589b76aac9a1" \
                       "075a8764888361824f04dd53806d09f373f9657e8f13617e6415f9f746e84df9" \
                       "630fece384df0355e2d1df28036e6f6295640f60fe92d0a8529b3c5161a3c701" \
                       "0f232a4464d70f8aefaa9488044eac2077cd43d2b2f25c7e704ec61e034a6cbb" \
                       "bb5dd70bec4794eb1e33e5ec5107761347eb79070709cfd700745fbd2d766e4a" \
                       "581fb586fc3bb9eb9e77363bb0d7fcf344ba8b07fdb83b688713753a26bda80f" \
                       "783c0ac2313768b8c7f67d043642c6ff957c0583e3dd62aab59bee3e5cd1bc04" \
                       "72068891f1e77a2f35f160b208bd7d3df547a1fd872bd18359261d2a9c5901e1" \
                       "a28cc901b16949d56434daaa209811d8f11def3138f0db8c6fdea54b3ab583f1" \
                       "95877b684b11858027e93c6d20ba0cc0281447203b1c61594eedcba49c6374b6" \
                       "01d6c0979fb38aba8ee9d847752261bc7c94738516f918c383538deaefa3269d" \
                       "534f603c403299c895f50cc4d474da7f6987a371cc34ff30db9f03794f5d2488" \
                       "316c2aeae6cefa11dcfcb0d4378342dc20e818354def709e08ddde8dda55c15c" \
                       "04a8bbdb0a56118a4b94a9235005d559ddaa83576fbd3e328d2561f9e72f1787" \
                       "da22fe90f7a376d87b04c6f72de9efd48b2875db22338665880d032b233582e3" \
                       "b9e2e30c69d307491c5e135709d0cb245bb2a55f0867add515ff4cfd35215915" \
                       "a1aba36399e714b616e2d9b2a284cee93bcd8e61f42f6ffe8b0f5d34ba5805ae" \
                       "db2394eaad90c2e665825e090cb2a5e383ac05b6e7234425bd7d55fc468f4123" \
                       "7411d28db93530e688e7199e4c1c2596e5092cde769a36d78bb55dbd9ca0373e" \
                       "6535dd04c511cc2fae15c93536e5176060642fa2e110d828206b49b5930b68b5" \
                       "c42100c9d1cff192412d5b8b14e32e1fedf304b7f66244fcd946f25740d57f41" \
                       "1a877eef40fdcee05b86aa54bfb21acd7113de786bf0a7f148db63c3bf01e74a" \
                       "b1430ca354ccfd2d099899822d0d4d325dd0fb986b0d15adbc54d6314834ba6d" \
                       "c13a420c96d9f50f7dbf9d19fe406896e887427c26b45893a0b8b5d31df52a3e" \
                       "e95da73cc854d1ab10f1effd88f7cab735321a108300d7978c0e62910876777e" \
                       "865bb74275316302c8e6d355efc6459b65a7f5fcf7a5b39db4abaa233579ed0a" \
                       "408e1de241bf033ad3c5986a55ca6f9884cdc89f6d2d7c93741849aa52a9ba21" \
                       "561a5f01e371aa51b112fce4eaaf8c84ab44a6d24c5748d511f1cb1dacf09097" \
                       "1861bbbd730ad2f98bbf7209012ba4c53cde7d9db868ef0608b3b596f28ed9cc" \
                       "c14efb4801889ee0b9021949acd69213df86ee19ea091e3bf9d57caafd2c6a04" \
                       "e588d4ee3f944313d962a043a8fada177f1643a699ccf6a2f93f11cbc9b58aac" \
                       "80339acb46f537b4a375de7765143c4af19d93c55b918b03616ddb41c98669f8" \
                       "d23de081b89ca9d678b9fcd74903b2a7db3862e4d309dd4eedecf9af421f65ce" \
                       "be99c8350d3b37efc3679f44e2b1f8bb23fa0d2138c53d2806bfb3bc999ba9ba" \
                       "990b96ed975ed2f93ecb144a14c803c4cce39774ebdc0f22b9d1f68b7f3f8d75" \
                       "69763b18dae79bd7f6f4d8dfb567ffc0a6c779566959c9dbe9a717e2e6a1fa9b" \
                       "588dc8db25ac5cafccee16671ef40d05801ab6244cf014f77592ba53141d8586" \
                       "c2b584c2328d8532466c5ef31852236399eec772d5fef0696d2cac2917ffde28" \
                       "551504a4d9014b6c15173afe7a9bee985f8083892a9e5189c7ab4931dfc91927" \
                       "0e04541400b2331c814d0226ed6fb7e6fe948fe2ffb593cdced2b158d1431021" \
                       "701ce62701ee46406c1002a7fbd2e2490cba26b4e03ad39ae9ff7c9951da4d33" \
                       "3d2c4d7ec2aabba772a8141b09c75e1626fc27f6b8dafd00de7647fc1f2badb3" \
                       "fabefe7f23fea16e69a117567284dd31d962b3ed34a28c5dad5a68f3e419430e" \
                       "128d616accb4034ca986d8a8acae8c36773241191f7680b30237d33a6898d9cf" \
                       "411ecc235c672f787b7989cd66e956d2357e2e23047af0591205b30d2e16d6bb" \
                       "c4716bbcc72eb24eaa48c67a3d8e870b75a5b54185c76f98eb8c3e99c7841dbc" \
                       "9bb9d35a52793e8815ea8d837b62875db73e20b1d9f6c5f9477f2fc66cca0677" \
                       "9f87f35c243af5cc27162f234250ee382d0b8118d6c6ef9d4ed060a2eac6c2e6" \
                       "00e498ef28c66c610635db7c856a3a8c2a3fb5b0fb0932770fd7145ec30f8284" \
                       "0fe3ae10a71434bb6b110ac97104200a7eabcbe60ff61d248d7f630e2d9fcb67" \
                       "6b0727d06d5aec6d309a5c3970c8ef6b9958d1a828f6b1c85d60467ebf50fe08" \
                       "2f117eebfa14aeddd4722f703c43c8e7bb18e59645c41b056d66eda5f4bae35d" \
                       "c229b8631103c0f3d7a4c009f062e11a4376b03bb36b20508a7c2c1b2ebb26fc" \
                       "9814605b3763db1125c547a51c9a14a85c51516238b47559141bd49b23411b73" \
                       "88b0529882be6489148a82e8732d581fc342fa755fc13eed42116cff9317e4b2" \
                       "db6500dbfdef858587a55676da83f23dae9804f0528ac745772ccdd6bbcc3511" \
                       "ec387c8e4d412becb3ab2922b37b1ef1bba9bcbe1ceba3c088e9f8ead229dfba" \
                       "8c3f38ca96cacd9230ac86abf3dfadcfaa132f2dfe93b83d1e1ca5cf4bae0a8e" \
                       "fe7a2af3b161630588c025d5a93b1049b7cfae978595f81ed191fb7a55059574" \
                       "bffc38ad450f079ad2fb82b83f8c2bc9581a6adb1b4adc515851c458d4e1c1b7" \
                       "124ecfe4a20ea03c4ca1fa563b24c2d2dff64b61f648a6a827432938f60d6b0d" \
                       "e7c75ccb64977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                       "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                       "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                       "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                       "9548769d"

test_signature_TransferToken = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                               "c5409ec20c544b7348356242fbe09e2e16a3ae7b4583559486834b9f3503974a" \
                               "a4f799765c2a85c8d83a2bd0b908eb089bae32698ba42f55ef81d58621a99e5f" \
                               "4249531e366869103ee0b5821deae396675c190ba006b71b2b0eb58eaa109b70" \
                               "36013669a708756d939de29ca1cd978c56aa482909221d0efb5d05d37743d3cc" \
                               "588f1ace1e581cf960c6f16c24b83b0ca3c897060e1599ae158290fda133c9bf" \
                               "182550865e184d46e2767279fc1abb5799282293200ecd989e3840c1d16e3d52" \
                               "6d30b8966a83ebcaf1418846ab3fadb71c39a24d18bbf7b64afa71f0a8f109fb" \
                               "edf702fe1bde323a5272cb95f9c0b87db52609922d92900e215d99d2d516243d" \
                               "a0e538f1cef6c6b5d8e0556b2c5871bb2e20d32a3bc12973b595666870367f83" \
                               "455583dbfae7a32bc71f2ff6a7e70d0f0f8a2a0a55dace6b087d4144636c5bb3" \
                               "7dee3350acf18254f9ac2b49b4e6ae9d65b1ca7ec0f0a293b256ba83b9845276" \
                               "1a8dd6b377e5dc46235152ff3f39c51f91200ef13f10f40343ce0ef5b5624b96" \
                               "33a81ca8d71bdf809c18ab6ba3b2086239793c9120979bc9fc09a539e8b62aa9" \
                               "66a59fd696f13e43b279af18029227b08b6e9466578ec4e127d3c1511b224ace" \
                               "f913586c43f9bf9b40cd9494986ca53463765318257bdaefd74602ce964de627" \
                               "a31870341c752e2b4ec071716c4d4859ce7486fadf89cd00289b3ba85fa89faf" \
                               "9f642ae3670ace537edea432b681ffc32e8600c65df0665d4cb6cd55b1508e7e" \
                               "b66b41843b38d2fa0b3a89ee35f0c7cff0808e2654496f2ab0abcbe2e83f8b18" \
                               "ed1ab373ffd27a1f625bdd6dc118888c5906d89219f38ada1ed5741cc8a40b81" \
                               "c41e7361b5da80106efcaa1c7c8b679b780124fd469b2b69ef8f6f3e91c2a976" \
                               "e08cc9d954f3457e2ec69f6eecb4da6eeab493ccb7c9da87a60212f0e6940cb1" \
                               "92bed4bc2fa256c571f47c9b5525cfb6cd710270692759a393af7b1cda7ce68f" \
                               "afcf36e7357358e6fc54cc21ad18a5490436973a1bc40dffa8e6430e97089d68" \
                               "7f8fbcbffbc17854adb225f2b55a031a57740917cb96d027697418ed2839fce2" \
                               "79d7d2a2de792482d40f01c662ea90bc4d073c3959103cd05f93ff6f33babc09" \
                               "0185eb1930579a34b5eb6a60fbfd39cd466949f5b7ce95d5a9a0c523c67af66f" \
                               "050c29d1add44adcd73b62c8e88a3d41c529ab704300638ecc7a8036d560057e" \
                               "8117342ab4058485f00e656c84a66e451b75d8eb13f580d5d032514f7f6d24ad" \
                               "739e045f64ecd664debe37fa7bf01b99d501dcc2365ef3595d56a4f9a8ad96af" \
                               "e32d820e53c2d6cc73508a2ade3aecedc1d37480fa8b152abc6cd588365da410" \
                               "09c419bdfe1f5adfc1253bde505148e684eab6e14252c9429a9d05a771fae609" \
                               "77c3efd15f252813fd78fcfbdb4f271a3a0aade4c3fab24fa035110e02b2bc19" \
                               "d3df7032a658fbd5584c2aafd0279cd13ab5d8700980d496de10003276cbbbc6" \
                               "e9a7c8b2c4c601dff359ba624a7cb23035480c62ca712e6cd3ccffc4273b6338" \
                               "58b46126cb1c7249518bdd624fc90dbda70100d6e38f065c6609a0183405b810" \
                               "0b1966d5325edcb81807c33f10aa20bc221b124f4526438349ae920c55ea7e11" \
                               "c74fd4b70978652eb9bf044316e1ed41145d0da7d52cd523b87807bc6578ba49" \
                               "69006dc1c054bfc6f9b5ca4fa973d7500b81f78d361e1ac69a8b228952de8fd6" \
                               "709997cb7d79d54a21e176170149beddb60959b2f5573c412c0f10c7560a4d9e" \
                               "c941c3d8b2af238486edeb4a971153a971ef8dcd6bf2b3e063732fa949035bff" \
                               "5c9a81d330f3a0087dcd5cde80b3fa0eee653553859d37f864cda79bb2a61bf0" \
                               "78c729c2af21ec11d901ba75c026cde282a78cf336cc0fe0732fc347b9da5e89" \
                               "e1854c590ca00723c8a9b3f35a8f4832db8c1c3892085f539392099cd624a225" \
                               "90bcd707099214612f322c70482aa76c5fabe9e9337de0196281eff09665b88f" \
                               "9019402baeac1c93e8ed33fd193c23ba301d3125f778fb6ed134c8d66eeab41f" \
                               "80c8b8c15a87ada1616a0c94452570c36217b69561cdbb097490cc1ac17fdc7f" \
                               "624d6ab17dc1e7194515df76aed152b5c082d0a8d58671edbb40f31bcc48c1f7" \
                               "e81c5e9aa0f456955e3f090db44b2c988a769ba7ea0b78d8d23988d3bd9967dd" \
                               "a4d0e2f8d3fcfd1d7aab96c36deca8c9a8acdd818ac456c90d1ba0d0cc32ef7b" \
                               "1a7cbed7455961cfc29551dc48cacbf3acd0f61b5ea1794e2260616a9fb61de1" \
                               "e9153990f98f2afc1ae3d679b548a4aa5473ca9b96e8d9663d008fbe958a605e" \
                               "82b1aa7191eb8146a8d0fbb32fa341ee57d265224424aaef5c713d453306ced4" \
                               "536db4275807a35e055394d8d83ff02e448816293963ce1734ae28794b3581a0" \
                               "03a542d82926d5034f4363bae4ebc2135751cad563862af417665dac3a3b5b97" \
                               "7cdd07c71e47990dfb6eedd2488df04995b6d619b6080b5ddd2435ce6e0a8b42" \
                               "b0a07330ec30fc3a733414ff86ce57866e26a2e74d1f7d7d19eb16ed3f279dd7" \
                               "f8260aca76df7b4d79e291a164a932c2892680867f2e9e8fece506bb7fbcc122" \
                               "6af5b90c14a2d9ec30175cc019123515f22ac3d5ab658398cc37bf4f8c44bcf1" \
                               "cd6a1a1d421f55b0c24752df28169a10dc7ae2993014af1ef7c86a6bd8ba9686" \
                               "56763fdb9fa1823271452221c346135ec4325d4acf70a7f3900b0b2a8a2b472a" \
                               "5210c81b543a84559c7a1f732b2cea43127487a087537fbb885ef496c4747f02" \
                               "f5cad200dd23908abed9fec3cd4a0aa512d14e70e6042e74597ce7ac4c527bb4" \
                               "5058673f551b50278a166641f22deb6528b0e5c39b02b833d82acb1e53919465" \
                               "19225fe52d9d0f82942543006e21c7fa9d36ee2db29f6498c4aff057e69811a3" \
                               "3d243975661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                               "b3159b6137c346524a62c6016019f994320db4d29b98965fe56bc26bed44a556" \
                               "3fafe98f562f0a698e77a30532d91a9841d4e9ef78a78990c59e7fdfbeefc8c5" \
                               "d455d0c164977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                               "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                               "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                               "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                               "9548769d"

# TODO: Do the same for Lattice and Duplicate
# TODO: Write test to check after signing (before is there)
# TODO: Fix problems with verifications (positive and negative checks)
# TODO: Check corner cases, parameter boundaries

wrap_message_expected1 = bytearray(b'\xff\x00\x0000000027\x00{"data": 12345, "type": "TESTKEY_1234"}\x00\x00\xff')
wrap_message_expected1b = bytearray(b'\xff\x00\x0000000027\x00{"type": "TESTKEY_1234", "data": 12345}\x00\x00\xff')


class TestSimpleTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestSimpleTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_index(10)
        self.maxDiff = None

    def test_create(self):
        # Alice sending coins to Bob
        tx = TransferTransaction.create(addr_from=self.alice.get_address(),
                                        addr_to=self.bob.get_address(),
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk())
        self.assertTrue(tx)

    def test_create_negative_amount(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.get_address(),
                                       addr_to=self.bob.get_address(),
                                       amount=-100,
                                       fee=1,
                                       xmss_pk=self.alice.pk())

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.get_address(),
                                       addr_to=self.bob.get_address(),
                                       amount=-100,
                                       fee=-1,
                                       xmss_pk=self.alice.pk())

    def test_to_json(self):
        tx = TransferTransaction.create(addr_from=self.alice.get_address(),
                                        addr_to=self.bob.get_address(),
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk())
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_Simple), json.loads(txjson))

    def test_from_json(self):
        tx = Transaction.from_json(test_json_Simple)
        tx.sign(self.alice)
        self.assertIsInstance(tx, TransferTransaction)
        self.assertEqual(tx.subtype, qrl_pb2.Transaction.TRANSFER)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual('b1301d3594083f83c413dd0acabd8d590124054f5057984548556fe14118f714', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)
        self.assertEqual(test_signature_Simple, tx.signature)

        # Test that specific content was copied over.
        self.assertEqual(b'Qfd5d64455903b8e500a14cafb1c4ea95a1f97562aaaa24d83e5b9dc3861a47386ce9ad15', tx.txto)
        self.assertEqual(100, tx.amount)
        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        # If we change amount, fee, txfrom, txto, (maybe include xmss stuff) txhash should change.
        tx = TransferTransaction.create(addr_from=self.alice.get_address(),
                                        addr_to=self.bob.get_address(),
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk())

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_or_raise())

    def test_state_validate_tx(self):
        # Test balance not enough
        # Test negative tx amounts
        pass


class TestCoinBase(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCoinBase, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.alice.set_index(11)

        self.mock_blockheader = Mock(spec=BlockHeader)
        self.mock_blockheader.stake_selector = self.alice.get_address()
        self.mock_blockheader.block_reward = 50
        self.mock_blockheader.fee_reward = 40
        self.mock_blockheader.prev_blockheaderhash = sha256(b'prev_headerhash')
        self.mock_blockheader.block_number = 1
        self.mock_blockheader.headerhash = sha256(b'headerhash')

        self.maxDiff = None

    def test_create(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice)
        self.assertIsInstance(tx, CoinBase)

    def test_to_json(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice)
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_CoinBase), json.loads(txjson))

    def test_from_txdict(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice)
        tx.sign(self.alice)
        self.assertIsInstance(tx, CoinBase)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txto)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)
        print()
        print(bin2hstr(tx.signature, 32))
        print()
        self.assertEqual(test_signature_CoinBase, bin2hstr(tx.signature))

        self.assertEqual('1992cbe80fdb9c76e5033d0e6d0547ccada465019cf1c31c7d583cef32801134', bin2hstr(tx.txhash))

        # Test that specific content was copied over.
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txto)
        self.assertEqual(tx.amount, 90)


class TestTokenTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestTokenTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_index(10)
        self.maxDiff = None

    def test_create(self):
        # Alice creates Token
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.get_address(),
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.get_address(),
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.get_address(),
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk())
        self.assertTrue(tx)

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TokenTransaction.create(addr_from=self.alice.get_address(),
                                    symbol=b'QRL',
                                    name=b'Quantum Resistant Ledger',
                                    owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                    decimals=4,
                                    initial_balances=[],
                                    fee=-1,
                                    xmss_pk=self.alice.pk())

    def test_to_json(self):
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.get_address(),
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.get_address(),
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.get_address(),
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk())
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_Token), json.loads(txjson))

    def test_from_json(self):
        tx = Transaction.from_json(test_json_Token)
        tx.sign(self.alice)
        self.assertIsInstance(tx, TokenTransaction)
        self.assertEqual(tx.subtype, qrl_pb2.Transaction.TOKEN)

        # Test that common Transaction components were copied over.
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'QRL', tx.symbol)
        self.assertEqual(b'Quantum Resistant Ledger', tx.name)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.owner)
        self.assertEqual('c8c2d8f98dc9d29d168f93450d865bd4fb806e764a68b0b1d9c1880d989cf51f', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        print()
        print(bin2hstr(tx.signature, 32))
        print()
        self.assertEqual(test_signature_Token, bin2hstr(tx.signature))

        total_supply = 0
        for initial_balance in tx.initial_balances:
            total_supply += initial_balance.amount
        self.assertEqual(600000000, total_supply)

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.get_address(),
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.get_address(),
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.get_address(),
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk())

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_or_raise())

    def test_state_validate_tx(self):
        # Test balance not enough
        # Test negative tx amounts
        pass


class TestTransferTokenTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestTransferTokenTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_index(10)
        self.maxDiff = None

    def test_create(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address(),
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk())
        self.assertTrue(tx)

    def test_to_json(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address(),
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk())
        txjson = tx.to_json()

        self.assertEqual(json.loads(test_json_TransferToken), json.loads(txjson))

    def test_from_json(self):
        tx = Transaction.from_json(test_json_TransferToken)
        tx.sign(self.alice)

        self.assertIsInstance(tx, TransferTokenTransaction)
        self.assertEqual(tx.subtype, qrl_pb2.Transaction.TRANSFERTOKEN)

        # Test that common Transaction components were copied over.
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txfrom)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.amount)
        self.assertEqual('7f28e2965e1a09c31399704eb5814aca8e973a87758570ae1c6ed083a2482e97', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        print()
        print(bin2hstr(tx.signature, 32))
        print()
        self.assertEqual(test_signature_TransferToken, bin2hstr(tx.signature))

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address(),
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk())

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_or_raise())

    def test_state_validate_tx(self):
        # Test balance not enough
        # Test negative tx amounts
        pass
