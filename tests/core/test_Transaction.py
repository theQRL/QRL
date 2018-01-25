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
  "transactionHash": "7beesRizKWnp1YJxDvN1u7xtUXlaU7wm4Dmxaa3C4Ws=",
  "xmssOtsIndex": "10",
  "transfer": {
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "100"
  }
}"""

test_json_CoinBase = """{
  "type": "COINBASE",
  "addrFrom": "UTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OQ==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "xvkMI2C5XC+6LWjuDx/D0DugFrxRKMoRgFQM1+Hnx4E=",
  "xmssOtsIndex": "11",
  "coinbase": {
    "addrTo": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
    "amount": "90",
    "blockNumber": "1",
    "headerhash": "cbyk7G3tHwuys91Ox27qL/Y/kPtS8AG7vvGx1bntChk="
  }
}"""

test_json_Token = """{
  "type": "TOKEN",
  "addrFrom": "UTIyM2JjNWU1Yjc4ZWRmZDc3OGIxYmY3MjcwMjA2MWNjMDUzMDEwNzExZmZlZWZiOWQ5NjkzMThiZTVkN2I4NmIwMjFiNzNjMg==",
  "fee": "1",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
  "transactionHash": "ebABJi2uyI/I0RQf2woLA2bsSu6/iL8BAKoSNHjlQwA=",
  "xmssOtsIndex": "10",
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
  "transactionHash": "R88cMCN4CqNpTTLzrf/n4W5qGNWRup8uOrtvtB/m+mE=",
  "xmssOtsIndex": "10",
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAw",
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "200000"
  }
}"""

test_signature_Simple = (
 b'\x00\x00\x00\nqv\xfaUe\xc5\x9a\x87uz\xc3\xa3\xc4^D\x84z\xd2\x98\xce'
 b'"(\x08\x9a\x1c\x9e\x0b"\xc5@\x9e\xc2\x1e\xaa~\x9d\xf9L\xa1\xbat\xbc$\x98'
 b'\x83\xadR\xef\x84l\x14yb\xff\xaf\x9e\xc7<\x88H\xad\xaej\xf4\xa4\\Y/[yc\x90'
 b'\xda\xa4}\xde\x92\xb15\x9e\xe2\x18]g\x13I2z\x86\xbe\xc7\x8a}[\x8cg'
 b'\xddS\x8a\xadl\x18:l#*\xa9\xe8\x99\xb6i\xcc4"\xfd\xff\x1d\xcfV\xde'
 b'f\x96\xae\xf2\x94C\x01o\xa3\xaf\xa5\xff\x1a\xfe\x8ai\xd2\\<\xfb\x17x\x00\xf4'
 b'\xb0\x94J\xb7\xde9q\x07=\x8b\x83\xde\xe5\xa5\xd9\xe4\x9f;3\xf9I\xf5\xfb\xd2'
 b'qX\xc8}9P"\xdfO\xbc,\xa4\xccd\x84\xd5A\x14J\xc5%\xdf\x10\xbb^\x18MF\xe2vry'
 b'\xfc\x1a\xbbW\x99("\x93 \x0e\xcd\x98\x9e8@\xc1\xd1n=Rm0\xb8\x96'
 b'\xfa\xc7\x8e\xe0Um\xbe-=\xcb\x07\xf03\x1cb\xd6\xbaX\xd21\xa2 t\x16'
 b'\xa2\xe4\xd7*.\xb0cG\x04\xf2\xc4\x97e\x16\xb0\xd7\x8e\x117\xba\x99\x82b\xff'
 b'\xecJ\x8b\xd2#$V\xb0D\xd2\x90\xd3W\x061\xfc\xa7z\x03\xec\xc2\x91\x1e\x91'
 b'!h\xa0r\xe2"\xa3\xb4\xa4\xf6&q$\xd1<\xd0\x18\x1b\x11]%\x18\xdfO\xadg\xaa7'
 b'\xa58\x89]\xc4V\xac\x11*\xfd\xd0S\xa0\xe4|N\x84\x86j\x87\x02\x0fU\x1a'
 b'3\xf2L\x1a$\xbeN\x11{\xd4\x8bx\xc6\x07\xa1J\x9e}\xfe\xe9\xfc\n/h'
 b'\xb4\xaf\xb9\xc5\x83\xaf\x12\x9e~\x80\xee\x14\x94\x87\xe70\xb3\x1fqh'
 b'\r\x84C\x8c\x9bp\x83;\x86\x97)\x89\x9eL\n\xa2.%\xfb\x0e\xe3\x87fg'
 b'9\x1c\xe8\xefx\x1a\x93\x96\xca\xe8\xf7\x81J%\xd7N\t\xe7\xd9WW\xee\xf9+'
 b'\x9a\xca\xc5\xd3\xc2\xb10\xaa5WP5U\x97\xea\xa7Z\xdb[:\xf8\x86\x0cs'
 b'\xad\x13\xa9j\xab\x97\x10\xe3#O"\xa6f\xf6\xd2}\xb1iI\xd5d4\xda\xaa'
 b' \x98\x11\xd8\xf1\x1d\xef18\xf0\xdb\x8co\xde\xa5K:\xb5\x83\xf1\x95\x87{h'
 b'\xf9\xc5\xccD/mB\xaf\xfe\x88\xaf\x054\xc0b\xdf\x19m\xca\xb6\xcej\xadhZ0 \xbd'
 b'"\x8c\xdbW\xf0^\xe1.j\x9fX\xd5\x1a\xdf\xa8\xd2\x13\x1fTU\xe9\xfb\xa4\x84'
 b'o\xf6664#\xa2\xd4\xeaWR\xce;8\xd2\xfa\x0b:\x89\xee5\xf0\xc7\xcf\xf0\x80\x8e&'
 b'TIo*\xb0\xab\xcb\xe2\xe8?\x8b\x18\xed\x1a\xb3s_\xb8\x93\xa8\xf0\x02*\x86'
 b'\xb0\xba\x9b\xdd\x7f\x05gw4D\xf5fm\x87\x92)\xd9\xcd\x7f\xfb\xe2\xf3\x19\xa2'
 b'\nV\x11\x8aK\x94\xa9#P\x05\xd5Y\xdd\xaa\x83Wo\xbd>2\x8d%a\xf9\xe7/\x17\x87'
 b'\xda"\xfe\x90\x9b`^\xce\xb44\x98\xd3q\x8c"\xa0\xe0\x07@\xf4\xfc\x99\'8'
 b's?:\x87\xdc\x0b7w\x1d\x052\x14\xcf\xe9]\xb03\x8cXA\x9fZ\x9d="\xe4\xdex'
 b'\x9ek\x11\xf4\x07\x97\xd28\x17"x\xdb\xcbF\x0e\xf9\x9eW!\x8cl(\xadd'
 b'\x7f\xc8\xffr\x9e\xfe\xe2<\xb9\x1dbYD\x81a4\x83\xf6\x07-\xc9\x99KOq\xac\r\\'
 b'\xf3%i\xb0\xd0i\x17\x8d~\x93\xcb%\xe4\x08\x01\xfa\xf8\xedH\xe2%\xd63\x97'
 b'\x15\xf3\xae\x10\xcd\xfc\xc4\xce\xf0\x95Y\\T4\x9f\x93\x95y\x15\x8d\x87j\x87/'
 b'\xd6\xcd\x98\x88X\xb6\x82qw\x9c\x13\xcf\x1btj\xde\xd96Ja{\n\xfb\t\x0bA\xf7X'
 b'\x8b\xd5\r\xdd\x84\x1b@\xdb\x1f\xfc\x11]>\xect\x1aoX\xf5\x81UBP\x81'
 b'\xac-j\xb4}\xa7\x07,5\x04\xa4[\xc3_\xb9\xba\x11-T\xe6\xdc\x0f\x93>'
 b'\xc0\xc5\xbd\x99\x1b\xce.\xb7\xbb3\xd2\x7f&d\xfc\xc1\xa4\x8c\xab\xf5'
 b'\xdf9\xfc\xd9\xaf\x9c\xe1a\xdb}\xe9\xccyH\x10E\xdaS\xb5\xeb^\xa5<\xe1'
 b'\x95\xa9\x1b\xe6\xa6\xf8\x87\xef\x0b\xc6\xa0\xb5\xe6Lc]y\xbb\x98+'
 b'B\x1a\xb8\x93Or\x94pA\x01!\xf8\xdf\xf4 \xf7C\xcf7w:\x02\xe2\xc4\x08[f\xec'
 b'q\xe0\xa6\x816n\xb7\xc3\x00\x81}\x13\x1e\x1e]w$-<\x91~\xaf\xe1\xd0'
 b"\xe5\xb1,\x05\x85\x9bZ\xe3\xbd\xef\xda\xf2_%(\x13\xfdx\xfc\xfb\xdbO'\x1a"
 b':\n\xad\xe4\xc3\xfa\xb2O\xa05\x11\x0e\x02\xb2\xbc\x19\xd3\xdfp2}\xecy\xf3'
 b"\x88\x18N\xae\x1d\xed$'\x8a\xd4\n\x05C\xe9\x8c\xec_\xfd\xa8\xec\xf4eZ\r"
 b'?O5\x17\xac(\xdd\xcf*\xc6y\x1d\xa0:k\x18{\xd19\xd3\xa0\xe10\xfah\xc8D\xa4'
 b'8\x9a\x80\xf7\n\x9d\xa8\x96s\n\xd2\xf9\x8b\xbfr\t\x01+\xa4\xc5<\xde}\x9d'
 b'\xb8h\xef\x06\x08\xb3\xb5\x96\xf2\x8e\xd9\xcc\xc1N\xfbH&S\x1f%\xed[N\xc0'
 b'\xb9/ \x0c\x86p\x97\xf7|\xf3\xed\xbe\x13\xab\xcc\xa2)*\x0ceK\\\x87\x0f'
 b'\xaa!\xca5\xb40({\x98iS\xbf\x89H\x88\xa0\xbd\x07\xd0\xf1\x1a\xf3\xe5\xfb'
 b'\xe4?\xdc,I\x96\xb9\x18&\xf6v \x15\xee\xea8\xd0\xfc\xa7\xb2]jhJ\xb6s\x8d\xbf'
 b'M\\:\x97\xb6\t\x08\x18q=\xd7R\xb8\x9c\xa9\xd6x\xb9\xfc\xd7I\x03\xb2\xa7'
 b'\xdb8b\xe4\xd3\t\xddN\xed\xec\xf9\xafB\x1fe\xce\xbe\x99\xc85\xee\xf4\xca\x85'
 b'\x94\x00\xedA!\x8f*\x9e\xa9\x1b\xd2cV\x90\xadYF\xad\x12\xf7\x8a\xb0G\xee'
 b'E\x162y\xab7\xabZV\x17\x15\xb9Z\xb9\xca\xa6\xef\xf6\xb0"x\xba\xf5\x80'
 b'\x0e\xfe\xc1&\\J\xacw\x88\xaa\x87U\x8ffD\xfc8\xf4g\xf5\x08\xd5#U'
 b'\xd3\xac\x91\x7f\x9d\x99\x8d$\n\xe5\xc4\xb2\x87\xce\x9d\xb5!\xa0\xb2\xde'
 b'^O\xd1a3\xb2\x8e\x1a\xb4;\xab\x1af\xf4\x06\x1d\x0c\xa5Cy\xd1Y\xceeu\xf9:{'
 b'T\x05\xad\x1e2\x8d\x852Fl^\xf3\x18R#c\x99\xee\xc7r\xd5\xfe\xf0im,\xac)'
 b'\x17\xff\xde(U\x15\x04\xa4\xae\xac\x1c\x93\xe8\xed3\xfd\x19<#\xba0\x1d1%'
 b'\xf7x\xfbn\xd14\xc8\xd6n\xea\xb4\x1f\x80\xc8\xb8\xc1\xfc\x12\xc55'
 b'\xf2\xf1\xae\x0c\x02_1\xb9Se"\xdf\x9d\x9e\xa4>d/b\xcdC&\xfbE\x18\x80\xef7'
 b'#\x8c\xf7O\xaabs$\xec\xa0\xa5{\xd9I\x04\xb9\x92*\x86\x06\xb2\x95\xac6bMI8'
 b'\xdeq\x97\xcb\xefo\xeb\xc2\x99\xa3\xdc\xcf$\x19\xfb\xb8$l\x0e\x15\xdc\x1c{h'
 b'\xc21~\xa3\xcf\x1e\x01!L\x8f\xf0\x1b\xb2\xe9n\x82\xa1\n\xc4#\xd9-_\xce'
 b"\xbd[Vkh\xd0\xc7\x8ah\xae6\xd1\x8f\xb6\xd4'\xc2L\xad4\x83Kt\xbe\x91\xa4W\xca"
 b'\xf7\xed\x08\r\xcc\x94yF\xd5Z\x93\xd3\xbf\xc1\xea\x89\xbc\x02\xc1\x96'
 b'rS\xb3\xcf\x08\xba\xb5\x15\xa2I5\xe8\xb6\xd7\x0c\x8ay\\7\x11o\x19\x03\x1f'
 b'\xa9!K\xc88[\xc3ey}\xc9\x0e[\x8a~\xe1?\xc9a\x01\xbc\xb2o\x8d|jUR'
 b'\xfc\xc6V\xf6x\xbb\xa5)J\xe7\xf13\x99\xe7\xac\x98|(fIzd]Q\x8aRr\x89'
 b'\xefz\xd6\x15\x0c\xe9\x8d}\x197\xae\x9f\xdf\xdfJ\xdb\x82\nN9\xa0\xf0\x05\x00'
 b'w\xa8\xc4Q\xdd\x06\n\xac\xb7\x8fE\xec\xfb\x89\x03\x85\x1c\x85\x02\x0b'
 b'\xbb\x10\rr\xda\x12\xc0\x17R\x8b\xddGG\xcf\x8b\xcc\x11\xe2\xdd\x0f\x868|\x8d'
 b'\xf0\xa7\xc6\xce\x0fpop\x91\x97\x1d6\xe5\xd5I\xa7K\xbc\xd3p)Bz\xd8'
 b's\xe1\x01\xfd\xc0nH\xb7\xa0\x7f\x7fC`%\xd5\xb5A\x9b\x13\xd1m\xa3\x98\x7f'
 b'\x86\x8f*\xd2\xdb\xd9V\xaa\xbf\xe0\x9eeq\xdc\xa8c\xc5\xbd+jN\xffBX'
 b'\x8e"\x0c\x9a[$\xc8\xb1\x847\xd7\x97\xe7\x18\xba\xf5\xd6\x1b\x9c\xba'
 b'S\xe5\x9b\xbfa\xef\x1a\xd6X\x17U\x96\x97\xef\x05o\xfb\x8b}\xb4\x8a\xca\x17R'
 b'\xa9c\x95\xf48\xb10>I!P9\xe8\x02L\x84\xf8\xb3\xc3\x88\x8d3\x81#\x1d\xdb\xc5M'
 b'\x13\xcc&\x88\xe0:\xd6 \xb3\x9c\xc3\xf5\x98\xcc\xbfM)\xb4{4\x9e@9\x94'
 b'\xc5\xfaF\xa7\\-\xad\xec\xee\x81\xaa\x0e\x1a\xc2\xd1\xdd\xabD0~\xa0[A\xb0'
 b'$\x8e\x88\xf0\x8a\x97\x19(\x07o5\x8a\xaa\xaf\xe777c\xed=\xca\x01\xee\x04'
 b'\xc9\xd9[\xb4/N]\x9c\xa8\xb9\xf8\x15\xd0\xee\xefc\xee\x9f\xdcV'
 b'\xb7\xdd\xe5\xa5\x06\x94\xe13*\xddwQ\r\x16*\xeb\n"6\xb7\x17\xff\xb3\xa1'
 b'\xfe!d\x81\xc4\xc2=\x96\xb45\xeb\x87\xf4\xd2\x193\x9d\xab\xc7\x9br\\\x80\xfd'
 b"5\xfc\x8b\xe9\x8d\x9b'U\x92\xfb\x84+K8\xa1\xcb\xd9'\xd8\x13f\x13A\xa0"
 b'r\xaf\x8c\xbfoY\x95\x92\xcb\x19\x12Yy\x90\xe3#X\x86T\xf3h\x08\x02x'
 b'\xb3\x15\x9bax\xdc\xad\xc3,\xe5\xdf\x9b\xa0\x7f\x9eG\x9c\xf3\xb5\xc3'
 b'\x9d\xe9\xb5\x94\xdb\xea\xf3t\x93\xea\xd6\xb9\x80\xb6c=V/\ni\x8ew\xa3\x05'
 b'2\xd9\x1a\x98A\xd4\xe9\xefx\xa7\x89\x90\xc5\x9e\x7f\xdf\xbe\xef\xc8\xc5'
 b'\xd4U\xd0\xc1d\x97s\x82\xe0^\xfa\x9eIw\xc4\r5\\*t\xf6fP\xdd\xd7j\x86\x03'
 b'\x18)/\x87\tWVs\x90\xb6\xec\xef\\\xd9\x18\xad]\xc6{\n\x06\x07+- $\x16\x1b'
 b'>\xab\xdb\xa3N_h \xf0u/\xf56a\xa6X\xffG\xb6\x9f\x9a*\xd1\x1c!\xeb\x81L'
 b'\xce\xa8\xdbN\x98\x9bX\x0c\xf40MG\\w\r\xf9\x10Z~\xb3\xd8or\x8e'
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
                          "fb2bd5932b87db84e6b3a6f1409ac91329f01f663144f5d4ef69c5d1b3ef7c5c" \
                          "139eac63e6d71227ed2011dc2a478dfd01d3363829a43577f940e0266f1d9ca9" \
                          "1dcc7571076b74f50a99a1bf6719048498056ea8ef80ff33379b3ee24554f491" \
                          "b90f4dbb44a52b39082730bc8ecd07b5bba2a986f9339107849d8df2b38d880f" \
                          "2bd63b7b7adccf9e1d0e947fdf3b3cf4403827dea423026f3d04d26c09470d70" \
                          "544e322b01154e3ee7f47bde9ec214da12bad06a33dbca4b253f76a4fd7e15f6" \
                          "23139db09b330dbf4a55fd883692f2bf6c93aeec039b1ead7b477e9ee62d6c94" \
                          "788341735d54e2b093e69fc360d77930089d9a596062e0c4649e1ff1151dd184" \
                          "f1e7ab7bac49f81c777a65aa476943f092644418d77160e92effb61990e3b670" \
                          "7ee6c589ef23b0b0cb2a4a27eabf340e51e63243e4393a0b9f4a14912bc69634" \
                          "8c182240f55f3fb5f87f87fa14267623b83303c6430c3acaa68c5903948a3d6f" \
                          "b7aeb4f2bc7e864404e81bab5d5ad88768634764665f48e306d9609482580489" \
                          "d852b91b45e6487a8d1d4b5e7132c65297df6dfcf884202de2c8cf4fb813e333" \
                          "45dae7facb62f8e1b9b399c8147ca34c92228fed1f5a64f9fb239ae6d316e1e4" \
                          "7415ad5ee4cba33a4a4187c3dbc6253d583afc32984d212f917a9716934361d0" \
                          "1700faebf1418c649545765d5925e588674d4cfc7e3cbb0baaaf6546c5e303ab" \
                          "25cd6cd44af10258e57dcc662dc5e69e25b6217fad5d997e7c51217a7e77583d" \
                          "5a4caacd183988618298f6ca64cd54f5cb3476446a3a7d6df41c13b18e77c2e0" \
                          "c2d1f811aa4cf2acee7b5f773d2f9fb8e6e95f540293f4ddeede05689ed0191c" \
                          "de72f0813a0d95c492043f4aa557a794ae5a6ebab7b4522b5663ff656c5947df" \
                          "8b30747eec856ce6cbc83f754179ca358e4c565dea6e09967474f3885d752c5b" \
                          "1e75587b4b2ab88f6377aa0321d6f8e99ee6fcdde223d02f232e1cca220bf360" \
                          "260b947013c76adc255a7c641a35fe7ece6afe274382f2afc7cc17db402e293f" \
                          "9ddffadd6922f3d0cceeeea46808e7636978871503406094669acb2ef8afe3d4" \
                          "6889cd3d8fc1ab2fe5de772f87b84bdbc88ffee976266ab236ffe81204d63194" \
                          "c2e898aeed4a7975514fd8507a63bc7806366e5114158e9f770996c7e9b12927" \
                          "fb5c43a91a73595fb28156881b05a8f6149e13656b1b1fc1ae3f786ec1aea146" \
                          "4c9692025e978b10dd4587d09872c5f12b82419d6a5784cd026f88ae2c2b7fbb" \
                          "2d8e918915143e496dc5a2dec48020b8381c5164e3d73646309f9571af0e58f5" \
                          "68fe591b1b4cad97fe49765b6e7e5d552051bc1bf27c7334f5fa3200ab276d18" \
                          "3d890eddd4c6550d1295bdda3fbef97bd1cd050170a658fed19a7315ab49ed6c" \
                          "1cd2d4e8226c972f1b5cd8459506b64c6c611a89afb3ef74b4b034b7418371c4" \
                          "b000be31f396b12366cbc8ac419904457a7e79a117499eb10c87782249e22197" \
                          "0af4d8bfd395126e666694978ab9980e6269832a1d632b1cb1a3c5ce9d959bc4" \
                          "bc2570c5fa324b56708dbfb5dc0519588200712b2f4d6f8c2f0d83d41195507e" \
                          "393a126f708f02b87283e8162407c11255ac40604a43eacc44299156a454facd" \
                          "376aede55de951754fdcade04a176d04922efefb26ec1af856eaf993f3a2f0f4" \
                          "9c63dd91308a911018ee93587fe3e01785e0b51b43050f5d369c794e7d9a5047" \
                          "a10cea240f0d952d7ca5346283351875276a075f4f6cf0d7a7e36c0e551f55be" \
                          "b3f5fbc83affba664d9979c0a25d7c887fcf97a78ad8a6a6da32b697b9aac425" \
                          "9f987b4ca1a5bd7a1ab073d74ff3cafe10d6b51394284c38a4d8d410f9bad780" \
                          "62f28e897f96771461a8b3d4aa1e791cce8b1da03385912672b040363104919d" \
                          "d631123d96fcf26b16e6d7e0c34daa966a61348e0062a93f259df3335ea0ae38" \
                          "c4671c0c6a2b381b3954bc06e05974ebe43f88fe0ee15b13ffde29841d1da6fa" \
                          "5e703773161e11d061ea80df67cca683f159f343efcab688ccb471ef8fe2501f" \
                          "4be39e1865839deaaf34c702535a11068f11fc4133297261f8b4120939d06308" \
                          "5fe5574bf757993565d5a676a7943b2b272a733fb1144d0183c2a0d5ac9a19da" \
                          "dba32ce9044e52a8a7d77396f198b9f49e5e71fa9de9592eca25694ca1e8e9f3" \
                          "82c37cddea6f4c139983911eef751a243aef1d1203a80fa99bb98caaeeac7914" \
                          "f3e2c4f05f58cc1182854ef3f282249db42ab9fb4b44a24f5aeacb242203c006" \
                          "c8ade60e10d1a8605d2e6ac1cec2b2d447060922ca3a55e1f7867e5c1de440c1" \
                          "433abeb6d017f5429d6f3b986e7d1984a04d7c184c43e4e15625824de8cdb61c" \
                          "855f8a64eecd6e4310331e32e2e3073efa66c23c1f1bafaaea729ecec0f50a07" \
                          "cdfc9d7964f199743c901496a0afd2636d9d656e3183a2b564658323833308f6" \
                          "e23cf5c9e7f7930c155d9a75ba95e00280498fe7af26bc510ccd64d52e64d0b8" \
                          "ca26e5db8d8f94f03b25aad6e2a3042ce2077538cd183ff9a930f8b10b05d32e" \
                          "065077fc7d4c1b8d6325ca6075d70f5a9e37f9398c0954f19d61679ec0d8836d" \
                          "4f5f85e5975dcda3fae3bf078812943e39a823e1f86a154052b7240c3d9c9198" \
                          "0edad8f9ad82d797febd0ae9395ee4a1756a918a3ba358276e31e706f139516b" \
                          "7581eb464c74612ec9a3f7224ad7df522334ebe0a91d7902a3670e19253914e5" \
                          "a913c05717dac74a883b5b7eb867477aa91e8415160b28d3560db95a2add28ce" \
                          "d8334690ccabe0d611ee1663c207abe9f321dcf583e46ea2d71fdd9a16791dbe" \
                          "f5923437e95c3db600f0b1dbc605128655a252c4111b84c28a370997c2de91eb" \
                          "6531776a9062d01ae502f5d8de7216df6969589d71d4d71f4650438773b66fdf" \
                          "a2b09c42ec9f46d51f5f290c180b387866e1bb965ba8d81b85a8bcb249f93cb2" \
                          "a3ad1f12d7c90083f9beccfc373fbc8a4ef6bdf513b63820a04c87d69a2e871c" \
                          "aebc5f4824221e5b212e67d0af41a706e59e3608b52917bcc0bf8b2990f20799" \
                          "e24fd62002a5287e14dff7ad53c21e16b62a15b2955584682c2aacf784908653" \
                          "f731168d90b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                          "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                          "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                          "9548769d"

test_signature_Token = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                       "c5409ec2b2b5f1f77bf93227bbdb0a701011bba0ef184bc11688edae8890e6fb" \
                       "8e3ddb77d802ab07d724d00e641cd943789d40305601ed925bef94055b31810e" \
                       "f40a86548d3961ca3a9dde367280c13e21bc2750b586186cca88c39ccda7cf14" \
                       "21936ce99067b58cfc2e97aa376c26ed4d3aff11a1ff8e9815d065d85154c209" \
                       "c5b5787a9b57232578c63b05905e6de2bbb8c18b602ba80dc0f942f11e7e520d" \
                       "45753d97753209750f0acf087af3a2e545a9db00e615ed8118790fd8707d68d2" \
                       "922899426d4d6ebd28a1aba9ef6eebd279eb1bf0c0c19ae06ecfaccc17c991fb" \
                       "0dd84bfcbc065764480a87c299b656a8ab792d2998bc24fa7cafaf09c893d39f" \
                       "a1f343dc93ceb8c8ee4ee8d804a6112916a0be0cd12c3a40e4600e2f4c0b01e8" \
                       "be2a37f12fba7cac68e2d00332a428212c6771d4dd00172a181529f3d806a137" \
                       "f82fd7f82cd88ba68df4579caf85a3a874202c8ab29030c81e1c57cb959b7229" \
                       "038c83d45ba73b9c20ae3784706b258f94ecbdf167d48654775c1991c02874c9" \
                       "16d7362fe49add621e3d9a8b08ab734055d32e51a4c4908d6433a6d5377bf5aa" \
                       "1156400b0eea111ead25f32e885f5f0c58cd6015f96573dd48f820e152fc5b64" \
                       "71cc9b5f455bf150d073e13f55abcd360dacaa139d616b0227fe4773989bb2d9" \
                       "95c0197e4b11858027e93c6d20ba0cc0281447203b1c61594eedcba49c6374b6" \
                       "01d6c0979fb38aba8ee9d847752261bc7c94738516f918c383538deaefa3269d" \
                       "534f603c27475044e060031fade3e658b6cc13f5068c2902e9494dafdb8d6229" \
                       "c595c3b0a89d907980f04fd500df0c83bd5f6a69c139d9e04f974d8af787a77d" \
                       "ce408e216fb31772c7745bfb8c46649189d9bb5e065ae21b468f21f3eae64077" \
                       "776ad299f76af3717a0ef175e75b8f44d390b58aa13f2a2a2ecb92fbbd4f3acf" \
                       "b50d9434c202eec83039badf0444b3632d6ec2882d1a1473e424f4c52ebd21af" \
                       "27320985426695bd3acb087d47c69638a86518a172d613aa24edcdb1c500b5d1" \
                       "c2f15aad7548285675227fb644c5b5d3339020cd8b7b9972d8b11d74faa92f3a" \
                       "b373ac982442b496356eb14d96786fb5a192314f97cd2f63dba00bdfaf46b433" \
                       "24f3811a3e2a8e53de8097d6736b396f1a061eed3437ce116260b1bced2ef156" \
                       "e726f860fa06a3d5b9806f7120686608d7e187387913f6a9b37adfb64cffff9e" \
                       "a188504656b857bb188faf9fedcc777f9685ed7b8b6167cb00fee05fbfb9ad80" \
                       "cfa67d0a04ad21c70492c3afb1e85e0a02656cfc9765d8e65f98063fa4d02a22" \
                       "e36aeab596d9f50f7dbf9d19fe406896e887427c26b45893a0b8b5d31df52a3e" \
                       "e95da73c2eb54e05c1ffbd8196f5996c7c43d0b39e1229c4836a2e357746b3bd" \
                       "3618c59475316302c8e6d355efc6459b65a7f5fcf7a5b39db4abaa233579ed0a" \
                       "408e1de2365cb4743bc957e7f8da351c2ca1ce734e8df8951f110d90112ccbd8" \
                       "5c2b060a0bcf0fab65134fbffe7b956ca9b8e81d846df16b4847aacceacbfd4c" \
                       "c59ddecd4e2a12b8c7c8dbed59480579c000d5fc90e5ab856a0fc7243a935d8d" \
                       "f5d3ebdd2131ccee1f203af4a1305e7ee11090add51e3671f350436f9364c841" \
                       "3c4ce88ca11720404f54c7f0acfe840bac30175545a5b3692112fae1300f68a0" \
                       "3646a4d3df4bcc292105c88b9e6d9cd821992d6477419721dc876cc1c7c9ab0a" \
                       "18197cfe3b905a087f644333a32b9f9d5955e1aac3fabed3125f252849c24812" \
                       "fc412c94e67b15c1fee81926873e25dd5255026b7eb41e38b4a7d99a0d88c34d" \
                       "bcc280f09c608c75aadee7d9ee36ca36cd9a174c4ca90f4ba7b3b9acc6f9f85e" \
                       "a0b8c320a2eec47d6755a12931d34050b4d1d550c1b88191b7018d8fc182349c" \
                       "a18581055e2b7facadea825626a059cd68bf8ceba8ba5b534b1821bb2c9670da" \
                       "43e9db55e864176357290a75a1fe4fe560d990dc7ea84da038efd443b2aa1ca7" \
                       "5ebed6660651be0e270990431e405fc6fd7551219f652b2edec33063ba9fe3a0" \
                       "7831ba2b5a87ada1616a0c94452570c36217b69561cdbb097490cc1ac17fdc7f" \
                       "624d6ab1238cf74faa627324eca0a57bd94904b9922a8606b295ac36624d4938" \
                       "de7197cbb6e08dffb700a0c361e5f092a3bf885d2545c3c9752d79c493572a42" \
                       "31487223745ad8faeab075e2dc2660036e54a4793ddd263bed79554262aba12b" \
                       "2758481265f2eeb1faf2093755254e0456f35adda1f8053dda14a8194e2797c4" \
                       "4b207fb0f98f2afc1ae3d679b548a4aa5473ca9b96e8d9663d008fbe958a605e" \
                       "82b1aa711223d93b59c69f235b6cbe77c2803aa68808fa04a62c5dcfa1c04ae4" \
                       "f46f32615807a35e055394d8d83ff02e448816293963ce1734ae28794b3581a0" \
                       "03a542d8839d8db5825ac1b168d95a474d127f6488d4d2378cefe1c6efbca67b" \
                       "22a51ac5a1ee5fb8712f68bdb750423979421aa8a65d7fbb696e62ca0fa3e946" \
                       "ba861a733e101b0709e60a5e6112c25b9ba01a93d4ff2335fa11c2663b411e3b" \
                       "c4a895704011fdaabdd8b35c8b77e7e44ababb3735520b9964a5af779dafab1f" \
                       "9b46baae14a2d9ec30175cc019123515f22ac3d5ab658398cc37bf4f8c44bcf1" \
                       "cd6a1a1d782eeff9deaf60d36d41231e9198b4efbb49e75089aaed2824e25834" \
                       "1ba1df82d6c7d6b285dd927a114510f35a3f2d51f29db6928b182cc5f08f885b" \
                       "7b323953af4a1430061c70100e4890427338843e30d3754d63ce18257293466d" \
                       "89d213942611ee5d43dc4f43eb113b668c1bf870fafc9b82554cc6696d8aed05" \
                       "8ecb4abecc75a1aee8fa323a877b7f90cee86c6bb906a0ca9ad333192f8658f9" \
                       "8199e4cccd261a025319ac46bf59b3d3fc557075af63fbca2bcf00a31920d33f" \
                       "0fb2c6b3661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                       "b3159b6178dcadc32ce5df9ba07f9e479cf3b5c39de9b594dbeaf37493ead6b9" \
                       "80b6633d562f0a698e77a30532d91a9841d4e9ef78a78990c59e7fdfbeefc8c5" \
                       "d455d0c164977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                       "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                       "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                       "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                       "9548769d"

test_signature_TransferToken = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                               "c5409ec2d5fb742ed01c2d73f14b75e508b342ba96547f6ee1b8fe9d2601b7ab" \
                               "e8c4a1734870a8d0281ec3cc3c4f8b70a0fa0ac31c67d06629bc4546365286f3" \
                               "70c7de3260cdfae743ea2cc950260c327bf0ad4c85b79fb176444b5b0bec8c8b" \
                               "c48ef8f98593ac64bed1fe194687ee6cf8e576d14c9167042fb7ddbb6475a6d5" \
                               "46ad297956ddb039d01fc342103227879adc69a1d057bedc5dbc272464b2f4d8" \
                               "fbd658acc8f2622ffa4f161834244d0e84a3229a9777cdf7b7d67da1eac9d0d2" \
                               "5d3c5cfa97c7cc5d8304ae8cae3367452fd68120507ade0e057f589b76aac9a1" \
                               "075a87648364326bcd51a379d85d00da2dd2a59595db36c82ff9049889ac00b0" \
                               "ac6944a084df0355e2d1df28036e6f6295640f60fe92d0a8529b3c5161a3c701" \
                               "0f232a44400d2d5698e40ebef7a17641a835f46e2916216e2929772b1e7e8f7e" \
                               "dc111080acf18254f9ac2b49b4e6ae9d65b1ca7ec0f0a293b256ba83b9845276" \
                               "1a8dd6b39487e730b31f71680d84438c9b70833b869729899e4c0aa22e25fb0e" \
                               "e3876667b5a70195d45db557f2fc4a36cc7aebacc56dfe6fdcc32535a5b0d77c" \
                               "8dfde48755a2ebdfe65ea701bf8e97db37a5f219442b0894d64f80a7a16fbed1" \
                               "318d0b31c658c2a60af7760ff9e1cd97b9127660c31cad47241e643069562bfe" \
                               "0b115e0307bae51abf62abadd152da4eea080af17f1190ed1dca654278690851" \
                               "8a44971af68b96484e329a83b9eb09909a02db59000c4a1628a94190b3d2046a" \
                               "9fc72c0d27475044e060031fade3e658b6cc13f5068c2902e9494dafdb8d6229" \
                               "c595c3b0ae8e6b66f7a4b8d50c4532fa61c478e15b5c535a9bdf23044c28671a" \
                               "cacd9a79481e24dc9c76fb68de25ab3f68c92285e79b85ad591636c0933e92a7" \
                               "e5458c5b9b605eceb43498d3718c22a0e00740f4fc992738733f3a87dc0b3777" \
                               "1d053214cfe95db0338c58419f5a9d3d22e4de789e6b11f40797d238172278db" \
                               "cb460ef97f12cb0c5e0be4b4314acf9900e3c66fee7682bb5814889f6f6d757e" \
                               "8fe2b136c9cd84c2f62aa90d38d47a7ea6859b16e6d11deffe6cccf8fc8368b9" \
                               "b17e32ccf82adc7b0d6314a2eba45872ab09987f93a28f842a122804c2a3cd45" \
                               "c62d6393f0d5e9306d2a228642c7ff9f07d8bd84f70b5d91be2094113abcd62e" \
                               "2ccedb6fd1cff192412d5b8b14e32e1fedf304b7f66244fcd946f25740d57f41" \
                               "1a877eefbb7184647ef32033c35adb67df144218006ba81b57abab5ceea6ba06" \
                               "942b96e354ccfd2d099899822d0d4d325dd0fb986b0d15adbc54d6314834ba6d" \
                               "c13a420c421ab8934f729470410121f8dff420f743cf37773a02e2c4085b66ec" \
                               "71e0a681ba1e421f32c7383ffe3eeae994c3b4097dd4993d2aaf4b789249a228" \
                               "7087d56c93782ee96fa292402b730d968dd98a258ef5c69c6538dd1811d9dca8" \
                               "c6e71e881a0b17e6eb6af36790f881d71e3b3a5dab4e5ef7934239cf3a31aeae" \
                               "f6731657852b001a2de53fc3f8b70cecee02cfa20f7571dc3c4956c88423a7a5" \
                               "de97e101cb1c7249518bdd624fc90dbda70100d6e38f065c6609a0183405b810" \
                               "0b1966d5c6c4cc8c74de897e9d8e3a8cc608b43076b4ed8997aef599f18a6627" \
                               "cb63d61da5bdc7a55f69780af5c3d45d1abab39cf82db310b0d93d309c446fa6" \
                               "02bcded7459ddec139b1bcc4bd03a7cce9111190759adc2d5338e91466189fbe" \
                               "2c79e0e37d79d54a21e176170149beddb60959b2f5573c412c0f10c7560a4d9e" \
                               "c941c3d823d251dc3d3e4b2223c616bd78e1af81fd26e77fb4de8543b88f9db4" \
                               "90529b6615e830315314e9b01d854418e1bc62a8ba9673df9193479fd832f2bd" \
                               "a424e2ee373ac116088c6d0d6860e7ba373056b5aba89b59419848522e538cf5" \
                               "fbb13c2409facf9e1bfa5d43407517037447563bcdc5283e6c6ae0843309d082" \
                               "8414989b811408aeaff7766da3fb29196ecfcc076c256c14e69285b03b543960" \
                               "be7f566d0dd9f19256a5a00c497798121333306b4a46869c9d38397a38509d41" \
                               "20b7dbe35a87ada1616a0c94452570c36217b69561cdbb097490cc1ac17fdc7f" \
                               "624d6ab188a8ecf6c2571e4793954e7a6a17b71f2af5531706a6a2223c162af4" \
                               "b9d9fc0a06906750834294141d4cb54c4bb6d070a13b25c5d9837b703b6a3a07" \
                               "0c1134c5bfed1232d7e0557d4592d0a8d388dc9f8a73a128867af0117222baa1" \
                               "2df9b9afe52e6b2314cc62e6e5431a1b5b1e2546db0f0dddf7cb430c4dc79fa6" \
                               "38dd0760f98f2afc1ae3d679b548a4aa5473ca9b96e8d9663d008fbe958a605e" \
                               "82b1aa715b8a7ee13fc96101bcb26f8d7c6a5552fcc656f678bba5294ae7f133" \
                               "99e7ac98f766851d229a1edbcdb42982128ac5eb45fcdc1dfd0e57f9dada2507" \
                               "fb9380c82926d5034f4363bae4ebc2135751cad563862af417665dac3a3b5b97" \
                               "7cdd07c77a5f5e9bda0738843eee4d9f52ba9fd05b3e40c45d09a641f605885c" \
                               "42bc7243525e9c82815c7061065a06994fc2cc66b6e99f9ff2c2d0175ab5127b" \
                               "43eb43c73566c7e409b69b8fe00a0e81bc02898e1c0f127d9ee0e906fc037c7f" \
                               "f0c373bbc62673f770b2691894193eae054652d09b63c6f85486bfcacbdfd169" \
                               "4d6b0ba6421f55b0c24752df28169a10dc7ae2993014af1ef7c86a6bd8ba9686" \
                               "56763fdba8a31fe08ea42e1976a3311c65389ac93de678393a2b81f0ee4a5e9e" \
                               "253debc2555cba657330e867d2be64eb7a308fda1981fc7c0e1181435b9f6e07" \
                               "cf322ecf5ae8bb80287c850ed40ee07964e701c76d921af0cd46a28f8b797a3f" \
                               "046de3faa9890ca4590d041e4d80c4526cfe318eaea8cddfb9a7fc62837aacfd" \
                               "c21d2b499b81d1f4824bff02f03d18506d73db3179aa7c879038720b26637af9" \
                               "6c919a66661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                               "b3159b6137c346524a62c6016019f994320db4d29b98965fe56bc26bed44a556" \
                               "3fafe98f689352c55b779b79d75cba315b43bd7f7eaf9594ef786b160ab94b45" \
                               "1e46c76664977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
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
                                        xmss_pk=self.alice.pk(),
                                        xmss_ots_index=self.alice.get_index())
        self.assertTrue(tx)

    def test_create_negative_amount(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.get_address(),
                                       addr_to=self.bob.get_address(),
                                       amount=-100,
                                       fee=1,
                                       xmss_pk=self.alice.pk(),
                                       xmss_ots_index=self.alice.get_index())

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.get_address(),
                                       addr_to=self.bob.get_address(),
                                       amount=-100,
                                       fee=-1,
                                       xmss_pk=self.alice.pk(),
                                       xmss_ots_index=self.alice.get_index())

    def test_to_json(self):
        tx = TransferTransaction.create(addr_from=self.alice.get_address(),
                                        addr_to=self.bob.get_address(),
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk(),
                                        xmss_ots_index=self.alice.get_index())
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
        self.assertEqual('edb79eb118b32969e9d582710ef375bbbc6d51795a53bc26e039b169adc2e16b', bin2hstr(tx.txhash))
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
                                        xmss_pk=self.alice.pk(),
                                        xmss_ots_index=self.alice.get_index())

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
        tx = CoinBase.create(self.mock_blockheader, self.alice, self.alice.get_address())
        self.assertIsInstance(tx, CoinBase)

    def test_to_json(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice, self.alice.get_address())
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_CoinBase), json.loads(txjson))

    def test_from_txdict(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice, self.alice.get_address())
        tx.sign(self.alice)
        self.assertIsInstance(tx, CoinBase)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txto)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)
        # print()
        # print(bin2hstr(tx.signature, 32))
        # print()
        self.assertEqual(test_signature_CoinBase, bin2hstr(tx.signature))

        self.assertEqual('c6f90c2360b95c2fba2d68ee0f1fc3d03ba016bc5128ca1180540cd7e1e7c781', bin2hstr(tx.txhash))

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
                                     xmss_pk=self.alice.pk(),
                                     xmss_ots_index=self.alice.get_index())
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
                                    xmss_pk=self.alice.pk(),
                                    xmss_ots_index=self.alice.get_index())

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
                                     xmss_pk=self.alice.pk(),
                                     xmss_ots_index=self.alice.get_index())
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
        self.assertEqual('79b001262daec88fc8d1141fdb0a0b0366ec4aeebf88bf0100aa123478e54300', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        # print()
        # print(bin2hstr(tx.signature, 32))
        # print()
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
                                     xmss_pk=self.alice.pk(),
                                     xmss_ots_index=self.alice.get_index())

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
                                             xmss_pk=self.alice.pk(),
                                             xmss_ots_index=self.alice.get_index())
        self.assertTrue(tx)

    def test_to_json(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address(),
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk(),
                                             xmss_ots_index=self.alice.get_index())
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
        self.assertEqual('47cf1c3023780aa3694d32f3adffe7e16e6a18d591ba9f2e3abb6fb41fe6fa61', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        # print()
        # print(bin2hstr(tx.signature, 32))
        # print()
        self.assertEqual(test_signature_TransferToken, bin2hstr(tx.signature))

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.get_address(),
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.get_address(),
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk(),
                                             xmss_ots_index=self.alice.get_index())

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_or_raise())

    def test_state_validate_tx(self):
        # Test balance not enough
        # Test negative tx amounts
        pass
