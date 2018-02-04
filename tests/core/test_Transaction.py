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
  "transfer": {
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "100"
  }
}"""

test_json_CoinBase = """{
  "type": "COINBASE",
  "addrFrom": "UTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OQ==",
  "publicKey": "PFI/nMJvgAhjwANSQ5KAb/bfNzrLTUfMYHtiNl/kq3fPMBjTId99y2U8n3loZz5D0SzCbjRhtfQl/V2XdAD+pQ==",
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
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAw",
    "addrTo": "UWZkNWQ2NDQ1NTkwM2I4ZTUwMGExNGNhZmIxYzRlYTk1YTFmOTc1NjJhYWFhMjRkODNlNWI5ZGMzODYxYTQ3Mzg2Y2U5YWQxNQ==",
    "amount": "200000"
  }
}"""

test_signature_Simple = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                        "c5409ec2d56c1b0a61e0f310a66a9bf3747783a0726872cfe3411a80358d4ccd" \
                        "e05b8ed0e8b2c454cdc95ae820364e5323754eea8d38ce644df8d9138843a4e6" \
                        "28d1c530bcbe4a9e74abe6cd6285ba25f577ef13cd53e8c20189a18c56d3e9c0" \
                        "67deaa7b9067b58cfc2e97aa376c26ed4d3aff11a1ff8e9815d065d85154c209" \
                        "c5b5787a1e581cf960c6f16c24b83b0ca3c897060e1599ae158290fda133c9bf" \
                        "182550863a3291d17ead98028ecced993f635273f219bd4feb4622341f45d1e0" \
                        "67d206b96d4d6ebd28a1aba9ef6eebd279eb1bf0c0c19ae06ecfaccc17c991fb" \
                        "0dd84bfcab3f720e9ba655de27d8821730e57a0697e4a7cdb34149a40c9777dc" \
                        "92f8f70257c40d4090f750d437e7d721ba18aadcd9a2aceb23c4875a26ed7fdb" \
                        "39b992e9962151fe79487f03715fe0034223d15fe66180403bbea421673a472b" \
                        "6286dd76a0b48abe3d03da946dbe7672004a2fe006eb60107bdb2cd3db3f0956" \
                        "87a5e4d46a466fd065998ddb145fa872731d126c8731d4d58065ced0f4888bbb" \
                        "91a965e80cea4c5d9f41f55acf74204389b6aa9811b0a4b6d6281aace38224ee" \
                        "cea7daec0eea111ead25f32e885f5f0c58cd6015f96573dd48f820e152fc5b64" \
                        "71cc9b5f43f9bf9b40cd9494986ca53463765318257bdaefd74602ce964de627" \
                        "a318703407bae51abf62abadd152da4eea080af17f1190ed1dca654278690851" \
                        "8a44971aa136ffdecd0d1a7b54e7fb1baec945879f22be31cb77ac4e766d9ed0" \
                        "047b5217320cb1e7150498288eb7aebd74a66a3bf4853b0bfed3b67b45c17b73" \
                        "da68e943253aa57c379c1ea03406d9e86082e3758656659d153903bdfd3e2eaf" \
                        "8fd0e877e382e479cb8001f9f98459229794f899c2a6dd9b993f806776920491" \
                        "b41b75afa0d0f361bfed2ebaaa9e5480a31989c63e7718736739a51a837b70e3" \
                        "d995e2298aafb47ae130415438bedb1874fb6c1d3f08ea3c8c80f089532d7ef2" \
                        "0fc8e996a707042055170043f84f389397e605d0c6f413a89691f67b7559954b" \
                        "eb4aaf7471ac0d5cf32569b0d069178d7e93cb25e40801faf8ed48e225d63397" \
                        "15f3ae10de792482d40f01c662ea90bc4d073c3959103cd05f93ff6f33babc09" \
                        "0185eb19f0d5e9306d2a228642c7ff9f07d8bd84f70b5d91be2094113abcd62e" \
                        "2ccedb6f447fcbdf663c0b8605bbb7f4073dbb490843269f3ecc55a569fc61bf" \
                        "0f35fdd520a7837a992aeab83c6344932956c6b9baa15808730598135f835b68" \
                        "27adb4b6c43075a454a2f03196bbfcd8ea5471d36ff1a89d31f65aeeeb3785c0" \
                        "8488d81ced2dda7d399fb3265d3d03817ba09b3a7bbdba09be5f9496d43085f9" \
                        "6fdbdbe5e14dd890f59d1c38796323485664eb9b68254e2620d9c38655cd3381" \
                        "c89801cfc9bc6400f7a23868b3bc3a62b69b7923d94f340888fbfaa70b3cc768" \
                        "afea51df1a0b17e6eb6af36790f881d71e3b3a5dab4e5ef7934239cf3a31aeae" \
                        "f6731657a1961c2b1550365fef453ef447701acf53bded7d72f51ba84d3dad02" \
                        "e94bd9f5ab99e01dae0afb250c6c0622b3d425496424fe41edd43fadc441abed" \
                        "e1117d505445af9368d8e4e5d523442fd21c0666fb75358f32aeb66c339bdbf4" \
                        "1f8d32323f944313d962a043a8fada177f1643a699ccf6a2f93f11cbc9b58aac" \
                        "80339acb423cf6be4647039722fa1e8c6a683853e820e231561bc517fc5d52ba" \
                        "537a9b81e9a3968291c244f7aa30a2de08b43306d7d4f4fab347583994ccfd9b" \
                        "69b74c2ab2af238486edeb4a971153a971ef8dcd6bf2b3e063732fa949035bff" \
                        "5c9a81d329344be664bcfdf9fde2b30b53cf12b8ec8f144c984484189ca00483" \
                        "e09f5fa33d04d3d4940370c77f075422e1207129762083586866b065c56e5836" \
                        "e788bfa209facf9e1bfa5d43407517037447563bcdc5283e6c6ae0843309d082" \
                        "8414989b099214612f322c70482aa76c5fabe9e9337de0196281eff09665b88f" \
                        "9019402bc3c1dbdb0031231f3a4739a1589cd6052b896115b4087acf06d35e2b" \
                        "649b5f5e2867d9547fff5da2f5ed0ead85dc564c4033464dc13a6d9833b3fe06" \
                        "5fdc47ef7dc1e7194515df76aed152b5c082d0a8d58671edbb40f31bcc48c1f7" \
                        "e81c5e9aac92ee6fbed25c5621401507c226fee6016cf03130b3a4e1bfe3ccf2" \
                        "1362a17123fea16e69a117567284dd31d962b3ed34a28c5dad5a68f3e419430e" \
                        "128d616afb11c05465424c37d075de97ac04dbf141f1f7101113e603de6c7273" \
                        "787265af31eac8209bd2e6b1e7443b9787483d884dcc01d7551d17df257bdb21" \
                        "c46a3ec216b30973ea9e735b8a8162cb94125ba3f0041c92b2226bf4cfa41090" \
                        "e6991eae0f903924c04224a7ee4f145f0409829c9ab687331839665af27d2cb4" \
                        "933f2a7d14f2fae9c4ea8337d46caecd306ab60adee3cff62752595de7ed1c9b" \
                        "1596c12104fc9c78cad7f97cd99bfd37a739a91714cbd03e9df018790feeffc5" \
                        "69b654ea3e101b0709e60a5e6112c25b9ba01a93d4ff2335fa11c2663b411e3b" \
                        "c4a89570384593c970dadd24db13bb8baa2949986154f8437ca3f881704c0c40" \
                        "d52df7ecfa14aeddd4722f703c43c8e7bb18e59645c41b056d66eda5f4bae35d" \
                        "c229b863ee392cee8aae3d3a0f6685879209004dee3ad2f38a9386625fccfbed" \
                        "8e7af1e83763db1125c547a51c9a14a85c51516238b47559141bd49b23411b73" \
                        "88b052986a09c27bdebfd6d734e8484cd496635225e9553b35d23463a93022af" \
                        "908506b17a8dc3b71feed3537560fb103f28d2770b3c3105adcbc29647a48e8d" \
                        "6cb593500a9894065dc6062646e61c2ab862fd23d72117ca25fa6ffb859a64a0" \
                        "0f61732dc2eee1646c71f87a24d848d0a0be51c8ca6044ff7d4bad2aa6986f0d" \
                        "28a43235b161630588c025d5a93b1049b7cfae978595f81ed191fb7a55059574" \
                        "bffc38ada5d89f4092fd36df8f74f596c74ae49367e8a00d2443e83d5980620d" \
                        "4cda383ca966fd6eb01782c47827ab868416bc66edff5648a3c0f2ee5cdd9b1c" \
                        "b534531b64977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                        "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                        "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                        "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                        "9548769d"

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
                          "fb2bd5936695a3b82dbd595265827686da506fa9a0976cb5bc6c0f1607de8598" \
                          "2aea5d1146479bae6d84accd0be74367aa983b8f1f698c4670e6c20161cfd9e9" \
                          "ef09a18e66938cbed36ad834e67b0dd9efe8203444b18c0249404cb6a005f4f2" \
                          "c8438a35d877effcfcf5a0037c63bd0978d443b4f8734ca8d4ac3d8a9e4d8cd0" \
                          "766668e956ecbd4a15ece78c9dee7087a778c4b80016e135771b8763aebe7e3b" \
                          "bdaea1fbd3a5a29cecf93c1833cf964136f0b87020df1234104867bc6f423c48" \
                          "92056626a039ea4ab96ef9c3952a31e1053d9505b1a7881a276a8a1c516b4c0c" \
                          "09a0a6c82cdc8f8f3f2a4da65470cf5ca0a06c9c22600d2e588c8863d562e83d" \
                          "a067fe639358ea38e165d6971e324d02f5159ab5681f83163ba0268bc2fe42cb" \
                          "3addf93ce4a7105bdae82da05ad0dcf5222a21565e91db94c2fc7206840ea587" \
                          "9de6441a46937da2d8bc652170dc213e0997ad1fb658e9cfd2bb4b273647c946" \
                          "8b1ad374ca467f3a72574b14a0b558c73ce2c4ef84c76fc5ff3d1a7c2d5381c2" \
                          "eb61af945600962bcc800904d9494ccd53311fdaf32cb58308b2ee5416c6078e" \
                          "708b69ba3964a20403c146d2f21c951b7a6363deeed65f69c82c256477c5a2cc" \
                          "219b6201932d40296826f94672db68eb504f6051618a311c9bdd767e4864181a" \
                          "75e87d8c4840d6ecc04992f1702e200e2d66de880a531a8a504af56e607cd31f" \
                          "f136b37a4af10258e57dcc662dc5e69e25b6217fad5d997e7c51217a7e77583d" \
                          "5a4caacd6aefb35878f8be43cb96c61ddc6288ae480b061142557857de806bc9" \
                          "10f1622702d4398dbc8a38b1bef383b3373d4b4d49830e10dc404c9b1f78c23b" \
                          "18fd2d9a3eb9cd09a232736fd75120cbe6960453f8cec71268d237e4b0d3e424" \
                          "db66a0047ac8b4f15f015c19d50cb1e553b214898bcfd515083087a11340dcfa" \
                          "f6b331db177b837d48b7dd1ca2ff963057730034ea30656cb3efbd060ef938f9" \
                          "60cc0883d3f6b131c680e6237c264887d4909b62a3b43cdb6e682bbdda34c445" \
                          "e3e7346194e8d3e9c6b741b72ef56139912b89d851ec18a8289fd24d0e44ba33" \
                          "970e6fdb603300c573e2681c757999e4ef012bc5e0e25e329cb59df41bedcdd7" \
                          "4d4912650f2b1fba7177c9c11c15ddef12a1a7c0c89cc5e33a9e7478cfd70404" \
                          "a3b1124b6aadc84116c21aabc82d8accd7a1aabb2bf4afb2e1f84c6f41113894" \
                          "92949a504051667bd68786cbba7fd62890d33c574d5f5f9dc49316490bfa6241" \
                          "eac7e2faeb8ce3ce84fd97c8af7ac1e9b21ad02822c9aff009f76aadee6abeba" \
                          "1d66f935541e25d5acbcb47355b40f95605a9f9253e83d72b86977b70feb9e86" \
                          "01723e0a5997cae1e86224665bda09033fc1a631483167017999e48df24619c9" \
                          "fe66f2535bbc94a30bdefc9fd6c1b60eb6eea5c262b62d8b838e6e12811489c9" \
                          "74d486192eecfa60d06af1f6416c6a46b5e6e888cb00a13c832e86802b674bce" \
                          "c1e26a38f597af70888d3da9a11ab105ae65a69ad571d5989441b24041ea7a89" \
                          "f01b446b367512515694402278ab54d509167146ac8096f2ced506cd0682ba6b" \
                          "ce2958b36e92613b1ef8a3a2d8fa1d8fcfe10aa9200ed1d6ba6223f92d9cbf23" \
                          "1b66a67c1aacd2b8a674f03b0ea087a90ea8ae7cbb92d6f89a9883b106e78ed0" \
                          "c1abb8b8308a911018ee93587fe3e01785e0b51b43050f5d369c794e7d9a5047" \
                          "a10cea24803d67b980a05d03081e671e0b8ed3709158d093a102958b2b21f042" \
                          "879766b7393de7532212ba1671b16c89985d218637d8deabf688e3b30dc24de7" \
                          "03d3e19a746b6ac53c1d04f2052eaf23912d5b11ae554b794ccab261a7993a87" \
                          "ede1119b743f93a581cbed16c0b2f9ff48d7368954cdf997673dc7db1cf58170" \
                          "a90f4080fdc248e10b7541b2144d294c4fd38aad4a7a525e3a592bc40b3df568" \
                          "6470ea4cd6d07ff1d97fdccd96968944f8104c8f45fd22aee9a192db87816641" \
                          "6ee3e1a2a1d6b7ac5f8d318b3555312df73d9b76ed849c1ea5a888faa1168d52" \
                          "f31995d0d123b1fbc00eaac4ff45edfed4f8af24149a16cfc2999a1f8c68e932" \
                          "6b29e20b3ad28fe6431fd8261436641babe5b989dfe47b176881437dec19288f" \
                          "8a5b083529eb9bca759135ae46421b253c64bc7cf9e4d024e4bb818a5dca4bb5" \
                          "287b0bb73c66a06c7e3394734cf3e721fea00268b61ad28cd23cb214b0fa1cbf" \
                          "5804b75218d0ab85f8c25b026be31e56bf11761dcca2bff6f32a2a45eb8c8bd3" \
                          "d031270910634224477377b53a06c9611299af1ffcea6ade3a59856025873bb8" \
                          "f062f0a1435ffc6dbd28c2c470ad206a53fd5e69ee8bdbcc33cd4ea4bb64283a" \
                          "d24a72b7aa1ce37dcde61a59c6e738d00c6c5b7ed36b52cb67886e21da4856c5" \
                          "cc53cdf0f273b4d1aa7f5713ea00eae6b33e610dcfa2e0dfba426979cdbad17e" \
                          "c1cafdf22d7f79ce13227bbab0a801218e04d6d830a2d2da1f51046ac9645987" \
                          "a815c03acbfa0973605cc69951de20fb00d7ac06ca8f9bde3d9e75840c721715" \
                          "681b7932cc6114d3a9cb691ce081cb6dbce2641a1353558682f0137a103e7df4" \
                          "75e3c21665b5b322fe2f29be6b10bf456dd1e7083e2397c1b57458b3b5a01485" \
                          "ee9fd91cf405ef96cb6e202c114379acdb0134baa0f0dd71a04b3fd8d7f677e5" \
                          "765f05528d01eed11e8c74cab926a2a74c43ac98542f0bfd28b3803779788d2e" \
                          "6a7d3c90f0a399f37abf6d856b5ad8d8853c8765496f976b32011a65f85b5f44" \
                          "0131d431ccabe0d611ee1663c207abe9f321dcf583e46ea2d71fdd9a16791dbe" \
                          "f592343771a255af93acbc115999729169b3edd3780fc7208c8b632dc4045e4a" \
                          "8022ebcf44fa39e7bab289c54995f904dc7fb27e79a4630aaf1698b8640bec7f" \
                          "b5f21650ec9f46d51f5f290c180b387866e1bb965ba8d81b85a8bcb249f93cb2" \
                          "a3ad1f12123b097c52147db253468b369eb9928bf7509e389314db59443311cc" \
                          "f177006ad66a8a41e1723d24185c56bc94fbde71a393c255729f1015f373aebc" \
                          "f539089002a5287e14dff7ad53c21e16b62a15b2955584682c2aacf784908653" \
                          "f731168d90b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                          "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                          "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                          "9548769d"

test_signature_Token = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                       "c5409ec21eaa7e9df94ca1ba74bc249883ad52ef846c147962ffaf9ec73c8848" \
                       "adae6af44a54ba4ec4dca4c0fdd9dea218444930f47fb0c915af470b0759e7ce" \
                       "4018e4b81543f2f17dbabcbbfaa72ebb0f7a4d8d04f4853bb07f12f3fff4185f" \
                       "49aa2e16182decc00ffdcb18fa866fb08bdf6f44c03ad0117b37d76fb3190847" \
                       "b68df84f9f3b33f949f5fbd27158c87d395022df4fbc2ca4cc6484d541144ac5" \
                       "25df10bb0cb08d702d8be4cd1907b72487823dd61f3f36758f3350bd845df403" \
                       "a46da6a197c7cc5d8304ae8cae3367452fd68120507ade0e057f589b76aac9a1" \
                       "075a87642444464861fa0409884ff880c329d35c06e5a8762963058ec1dd6a49" \
                       "27805adca6e24e0cb9debe093e528b6619863a7cfb11c80e0d0122b9851e55ee" \
                       "07bef0132245194ca27650363fc0a0e29f180b5b134563df13a99bfcc1270bb8" \
                       "408122c8a5e64ccead136b174c496eb8f7083d00c825ecffba2d40798ccd7cfe" \
                       "62ea7b85ae3cdf0abf23e8aa448e15e5ae89254923a6cd9db76f156f74436440" \
                       "fce2240db0a6a47ab23308170df624bd8e103b748e5e9505a0fe3732771a5291" \
                       "cd766a3c060f10f4ec80643213ed5cfaf3f64b66c585ef0eb5c6d54da3d1dc24" \
                       "1551df80b16949d56434daaa209811d8f11def3138f0db8c6fdea54b3ab583f1" \
                       "95877b68be48abeea0d0bd3218462fdf3bf37a4d5944f5d9b6ac8cfde3cf6ebd" \
                       "09a76c5108124c305fb5ef005775f93f29428a4dc5d1b50c2406c6b5f9e5b74d" \
                       "bd4b8b7e27475044e060031fade3e658b6cc13f5068c2902e9494dafdb8d6229" \
                       "c595c3b0ae8e6b66f7a4b8d50c4532fa61c478e15b5c535a9bdf23044c28671a" \
                       "cacd9a79b5da80106efcaa1c7c8b679b780124fd469b2b69ef8f6f3e91c2a976" \
                       "e08cc9d9ff41ece157a2d2f95c752d524904e4324581fff46ef44f57c21f4630" \
                       "8a406e5b181dc07da226cced854cc3264a6efc5f0a7434a1a6f1e774298f7187" \
                       "cd5b8daa7f12cb0c5e0be4b4314acf9900e3c66fee7682bb5814889f6f6d757e" \
                       "8fe2b1361b31eeb1f3d3db94c77e5a27b89dfc4cbb2f5582e711860e90a0de2f" \
                       "f9f5bf8d2b91cb5ffbc5d7cabbeeca71c20dd3053fe2e52452b5b7a07b6df93f" \
                       "407b146477a61c94f9555a29d8d87fbd09e0937fd78048c1433ed8dfce7881fc" \
                       "0708e447cd1b17ac827e4ceb151107d12282a67f88e2f278568c52924e834402" \
                       "d227e9dd2c21dcfa603d548de673006ecac176e4cf975a0d68123a2c334ec645" \
                       "d3371e5b278cfd20d9756e1a70e0fae1a8fb57e4eebd33a320d8d13cdf8c167b" \
                       "fc576592847c14b5b43b694b678c67376de3969909edbf1bc09a6ec06f4e8fee" \
                       "fc89e25a2eb54e05c1ffbd8196f5996c7c43d0b39e1229c4836a2e357746b3bd" \
                       "3618c594b56afdeabc8ac5f18c0dddab2ced6e46d5e62d0f71fa52d34f68ab18" \
                       "3b20db08cc4bfcdfd6e6d7f8cdb16f89e6f4c4f65a4ea2ca215e14771c0b4b7c" \
                       "de1b15ed852b001a2de53fc3f8b70cecee02cfa20f7571dc3c4956c88423a7a5" \
                       "de97e101ba1351ed26b9fe8947a694647c61f4af4ce02d2c396eae87e6593c20" \
                       "9bfd608a5445af9368d8e4e5d523442fd21c0666fb75358f32aeb66c339bdbf4" \
                       "1f8d3232cfb2fa5d0ed1865ebf2d84435d493964933a43c7d9f943d26e22b1fd" \
                       "924df71e78e6e11c25ad67676868c05b5a83c44b9a928e31d6e36ce30f70c1a9" \
                       "b2643c517d79d54a21e176170149beddb60959b2f5573c412c0f10c7560a4d9e" \
                       "c941c3d8dc0926f9225788258494ec4c2625ca21bde47132c75d8464d5f2805e" \
                       "4e7636449c608c75aadee7d9ee36ca36cd9a174c4ca90f4ba7b3b9acc6f9f85e" \
                       "a0b8c3206356d1f6adc14d0089dfbe1e5b212ee9f0315baeef42283716393448" \
                       "6ad358571c5aa004f4720106d9a6efacf3ed109f15911480e17cecea629a5d06" \
                       "88bcec8ef199b9bfa641d21fac3f6516b50398e5175a2a77ae97ddf817207100" \
                       "0c09201aa6361606ac7a90769a034969439d5d22999074613e5fb6425359020f" \
                       "7b26b6d0844362563a05106e1eaf9a2c946df8563da03ee006451fc8eb59e05c" \
                       "3fc2903401ee46406c1002a7fbd2e2490cba26b4e03ad39ae9ff7c9951da4d33" \
                       "3d2c4d7ec2aabba772a8141b09c75e1626fc27f6b8dafd00de7647fc1f2badb3" \
                       "fabefe7fa18eb5a12a6baf56bf83f5260b5faa7039c8f8532af25cb65dae4ef6" \
                       "dfce4ee2d7d89a98ce39d1d767925a6686c30e204d716758c3cae305698a309e" \
                       "4cdeeab78745ae43810966f24630ba2f1406bcfc6c32cadcb0039a9a128991e7" \
                       "2cf48c4561facfae2f7d1eb9e168ac573aaa7588f1b1b1b9e8796d6dafde8877" \
                       "6e93aa34211ec52e433f4a91958fcb24049c41fcfde1017bfd94df7e123b936c" \
                       "ec86604ea87bbb7d2e5f9370097e0cbfdb73c65e0c7a9d696787c45d5f588c69" \
                       "8c44837aa980dd2a61cd847b60a49f6aa7fe2198693d83c53370aa01c531ba68" \
                       "e196d4ed2dde0190c3cff28a9207c7f83eb359f401106c35d5cba999962a15b1" \
                       "efd20cf44011fdaabdd8b35c8b77e7e44ababb3735520b9964a5af779dafab1f" \
                       "9b46baae14a2d9ec30175cc019123515f22ac3d5ab658398cc37bf4f8c44bcf1" \
                       "cd6a1a1dd8aadd9b03b09c25ddab2839c6632393d90ab447e56013f32011cda0" \
                       "78bdcac3180472a25b74247041c13040a8936194d7f05e797a94ba3078a014a3" \
                       "c2f8b2ab06f2804d2414289b93f6743d8b4fec378b96cf64eea81f3a4209fd8e" \
                       "755cfe423763ed3dca01ee04c9d95bb42f4e5d9ca8b9f815d0eeef63ee9fdc56" \
                       "b7dde5a524e0b028c31de0aeb05c8de26648ea11d03ac2c8a47e677d95f4f090" \
                       "eb24c40bf4d219339dabc79b725c80fd35fc8be98d9b275592fb842b4b38a1cb" \
                       "d927d813661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                       "b3159b6107ea796cac4c62073234462b51a0659bcd44e933cc073623a3d2352d" \
                       "25bc698e7ef5bfabc6b2c8d9ddad1af6d182e69f513fa08737e67b8a9fbe1219" \
                       "5566130764977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                       "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                       "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                       "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                       "9548769d"

test_signature_TransferToken = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                               "c5409ec21eaa7e9df94ca1ba74bc249883ad52ef846c147962ffaf9ec73c8848" \
                               "adae6af4d802ab07d724d00e641cd943789d40305601ed925bef94055b31810e" \
                               "f40a8654565c42f5b03b43694f8d6b116f72cd030f50d35cea3c83ba7734f742" \
                               "e4828e41b1d154792ccd660c240156418dcbe8a87d012616a4596069232ff1ba" \
                               "189ca09154ce113a9c6f828762129290b7912e552db1b622bddc1904e7199515" \
                               "5ea7dc03ee602b676e4a5b02ac1fd97432079134e1c19433b6aa002587f60c8c" \
                               "fd91aa749ca212b95309f6cade620da6c8c2ca392e507c55b4f4d67f4caef917" \
                               "3d9285eb85a1811d054e3d083678e4223ed38901758486d4e32a21c0d179ef54" \
                               "d6aa97e957c40d4090f750d437e7d721ba18aadcd9a2aceb23c4875a26ed7fdb" \
                               "39b992e940435c7d9a51be980aa3eb1c65c52bfe640aeda4f64454519fcc28a9" \
                               "afcb988a08a1f87497d718e7b866ba0428cc157d0ad3c49c621c552ebde57773" \
                               "ae4e23dbf394b669a3be1b73672373172b6d8568571c46919b66b9e2027c1036" \
                               "d738c6868a4425625c48c0761f2807bfe34c60d5d333e188b6980e60c4444526" \
                               "ae95011e0eea111ead25f32e885f5f0c58cd6015f96573dd48f820e152fc5b64" \
                               "71cc9b5fdc4e5fd212a919438d0658d41468cbe6f02d8e60f1d524239f7c8c1b" \
                               "ca9aad62be48abeea0d0bd3218462fdf3bf37a4d5944f5d9b6ac8cfde3cf6ebd" \
                               "09a76c519fb38aba8ee9d847752261bc7c94738516f918c383538deaefa3269d" \
                               "534f603c320cb1e7150498288eb7aebd74a66a3bf4853b0bfed3b67b45c17b73" \
                               "da68e94348df4de921c5de24a05452d936acf1ab1e1005927caa85b91b1c009e" \
                               "2fa537ccdd935ad2e694c69ce5862cb7a8e99c2aaceaef49b0c280bef53df548" \
                               "d4d561ea30a717c6709bd70091d8927d2636c63d57b71685bf0ddad405c5ef48" \
                               "b3549221c3787cce9bc543b01d970fd91961e82d50234aeaf00aa810f442e081" \
                               "5d261431a707042055170043f84f389397e605d0c6f413a89691f67b7559954b" \
                               "eb4aaf744a4ef7b9d5777713f42aff893335e75c2bbd2c2b2a6cc3ae16e31a74" \
                               "47f03301a01913a95793d1de7f90d6ec0d07e10d7941b95a6f007d9f83290673" \
                               "59c68637c511cc2fae15c93536e5176060642fa2e110d828206b49b5930b68b5" \
                               "c42100c98f8f1ea6bc235931aa92b76befc498cf8f0058095ec1cb85bda396c6" \
                               "421f8e55b4058485f00e656c84a66e451b75d8eb13f580d5d032514f7f6d24ad" \
                               "739e045f54ccfd2d099899822d0d4d325dd0fb986b0d15adbc54d6314834ba6d" \
                               "c13a420c421ab8934f729470410121f8dff420f743cf37773a02e2c4085b66ec" \
                               "71e0a681fe1f5adfc1253bde505148e684eab6e14252c9429a9d05a771fae609" \
                               "77c3efd11931c5abe79736bd9d769aa855b288fc7851481e43c46e36253779f9" \
                               "c19860ea8a75dbdbb1213c15c7614c3bbeb745bb1aa3aee2f3b272ea85394500" \
                               "a03107f1d8cfc73923d0fe39e34c638ef0a524681764c1417ffa77805dce054a" \
                               "b7b33e58a6a11ab8d4a5b9fe0285ddc482fcb6bc6a027ee838f08c50bccd728e" \
                               "ea22509f4365b517e610263bdc248782c6c008b8f632e5bf21da2fe2930f8712" \
                               "73cab56600efc7325e1d9294415baed611958439d34eb9596bee83d652f493f5" \
                               "b4cbe7b3582a526958548efb71f302e7ca31b425b417f681a90e6c91993ac0ea" \
                               "3964b49f288070021b060fb95c5e7817916355d8a60b9bc04df4e26d606fb7bb" \
                               "9ca7227a78f60e3d2764d6decce995cf3d65dd6d0ae7d413c39ea7018e88c683" \
                               "561faecd9c608c75aadee7d9ee36ca36cd9a174c4ca90f4ba7b3b9acc6f9f85e" \
                               "a0b8c3206356d1f6adc14d0089dfbe1e5b212ee9f0315baeef42283716393448" \
                               "6ad35857de7117f298aead0c92b3ef09bbdbdeedac7684cb98041b4a1b1c2648" \
                               "ed15aacc9b1bad1767ba1a1e3d6f5fd95d32c2b2de4ae880c3e7249bedd8d3f0" \
                               "15f3bb62f75385882ab24e44e4c5b5bee483d9b7987d8f7f5f2b5e929a338129" \
                               "0f9d3ba622326afe820c21b3621a9dd74705daaa1b20525864a215cd0d6159f8" \
                               "16cb5fd288a8ecf6c2571e4793954e7a6a17b71f2af5531706a6a2223c162af4" \
                               "b9d9fc0a4a05e8837cba272f4895592fd712a4a8b853ad4283580fdff264e9e9" \
                               "e2a825232692d21fe59faa68c4b57fa6e2e37a16539fd3a61e21a82b7268265c" \
                               "51cb93f0e52e6b2314cc62e6e5431a1b5b1e2546db0f0dddf7cb430c4dc79fa6" \
                               "38dd0760e0b30d77a3cad4055bb77580cb5411485bd254eeab03d1bec97e8825" \
                               "4161558bf3e7d89f80b0da70bcfa880dbf375839d90f1f8763cb50a669a7dc09" \
                               "a220b55352793e8815ea8d837b62875db73e20b1d9f6c5f9477f2fc66cca0677" \
                               "9f87f35c1404c3ad526d8b6c79af896e5d365761f223ed22bce5b4ac91854c66" \
                               "2cdfbb0fbcf6e939354ef1d4516761e8876f9322103e92cb80c3be20c1df3953" \
                               "4b786b050c49d72f2bcf87bad9f020e04aa092bddc51321aa4c52ed755a6ad53" \
                               "2d7828a701439fe994d2165467de226f7b69e1eb725d27e3dc5d65d414724b53" \
                               "67783c614fb5a19238ecb78c22866ab8b5d7bee01469a4bfdde19022cb2702f8" \
                               "562c508e5bba7fd22f6cc2f0a62dcd29a113fa27fc2ffb3210d57b36bba22e13" \
                               "173d1b71b03510dd12b382e78377454ff696a4b4cf729b018e734c02db947c47" \
                               "19adac17cc0b2e1926df2eeacfcc19b60ad48d3e664d85eb6247c5ba4ad3c391" \
                               "efc3bc632611ee5d43dc4f43eb113b668c1bf870fafc9b82554cc6696d8aed05" \
                               "8ecb4abe0694e1332add77510d162aeb0a2236b717ffb3a1fe216481c4c23d96" \
                               "b435eb878a72dc60ee0eb4da847aa3e919f1ae25f88b5187604718f60427bc12" \
                               "0bc07ffa661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                               "b3159b617b9ca205149dc5f5da9ccd64b31494fd1e97b2999626dfab885a1e47" \
                               "7c7f240361bff36411545af185ed3d4eeb654f5459b2fa76930889b7169718ea" \
                               "9ce59a2464977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
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

        self.alice.set_ots_index(10)
        self.maxDiff = None

    def test_create(self):
        # Alice sending coins to Bob
        tx = TransferTransaction.create(addr_from=self.alice.address,
                                        addr_to=self.bob.address,
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_create_negative_amount(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.address,
                                       addr_to=self.bob.address,
                                       amount=-100,
                                       fee=1,
                                       xmss_pk=self.alice.pk)

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.address,
                                       addr_to=self.bob.address,
                                       amount=-100,
                                       fee=-1,
                                       xmss_pk=self.alice.pk)

    def test_to_json(self):
        tx = TransferTransaction.create(addr_from=self.alice.address,
                                        addr_to=self.bob.address,
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk)
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
        self.assertEqual('cca3d7b7009800563b382eff29f4a2784c4c0936745b02276457c169ce48479b', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        self.assertEqual(test_signature_Simple, bin2hstr(tx.signature))

        # Test that specific content was copied over.
        self.assertEqual(b'Qfd5d64455903b8e500a14cafb1c4ea95a1f97562aaaa24d83e5b9dc3861a47386ce9ad15', tx.txto)
        self.assertEqual(100, tx.amount)
        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        # If we change amount, fee, txfrom, txto, (maybe include xmss stuff) txhash should change.
        tx = TransferTransaction.create(addr_from=self.alice.address,
                                        addr_to=self.bob.address,
                                        amount=100,
                                        fee=1,
                                        xmss_pk=self.alice.pk)

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
        self.alice.set_ots_index(11)

        self.mock_blockheader = Mock(spec=BlockHeader)
        self.mock_blockheader.stake_selector = self.alice.address
        self.mock_blockheader.block_reward = 50
        self.mock_blockheader.fee_reward = 40
        self.mock_blockheader.prev_blockheaderhash = sha256(b'prev_headerhash')
        self.mock_blockheader.block_number = 1
        self.mock_blockheader.headerhash = sha256(b'headerhash')

        self.maxDiff = None

    def test_create(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice, self.alice.address)
        self.assertIsInstance(tx, CoinBase)

    def test_to_json(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice, self.alice.address)
        txjson = tx.to_json()
        self.assertEqual(json.loads(test_json_CoinBase), json.loads(txjson))

    def test_from_txdict(self):
        tx = CoinBase.create(self.mock_blockheader, self.alice, self.alice.address)
        tx.sign(self.alice)
        self.assertIsInstance(tx, CoinBase)

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txto)
        self.assertEqual('3c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab77'
                         'cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)

        self.assertEqual(test_signature_CoinBase, bin2hstr(tx.signature))

        self.assertEqual('cfabb0f04adea49c175a4df8735419a813530d578738ee92c006702fa29aa9ec', bin2hstr(tx.txhash))

        # Test that specific content was copied over.
        self.assertEqual(b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2', tx.txto)
        self.assertEqual(tx.amount, 90)


class TestTokenTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestTokenTransaction, self).__init__(*args, **kwargs)
        self.alice = XMSS(4, seed='a' * 48)
        self.bob = XMSS(4, seed='b' * 48)

        self.alice.set_ots_index(10)
        self.maxDiff = None

    def test_create(self):
        # Alice creates Token
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.address,
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.address,
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.address,
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TokenTransaction.create(addr_from=self.alice.address,
                                    symbol=b'QRL',
                                    name=b'Quantum Resistant Ledger',
                                    owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                    decimals=4,
                                    initial_balances=[],
                                    fee=-1,
                                    xmss_pk=self.alice.pk)

    def test_to_json(self):
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.address,
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.address,
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.address,
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk)
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
        self.assertEqual('c2e286ffff76103dd4185a14625bd09bf92d246484617d60481dcfcd13bcc5c9', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        self.assertEqual(test_signature_Token, bin2hstr(tx.signature))

        total_supply = 0
        for initial_balance in tx.initial_balances:
            total_supply += initial_balance.amount
        self.assertEqual(600000000, total_supply)

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        initial_balances = list()
        initial_balances.append(qrl_pb2.AddressAmount(address=self.alice.address,
                                                      amount=400000000))
        initial_balances.append(qrl_pb2.AddressAmount(address=self.bob.address,
                                                      amount=200000000))
        tx = TokenTransaction.create(addr_from=self.alice.address,
                                     symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'Q223bc5e5b78edfd778b1bf72702061cc053010711ffeefb9d969318be5d7b86b021b73c2',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk)

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

        self.alice.set_ots_index(10)
        self.maxDiff = None

    def test_create(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.address,
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.address,
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_to_json(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.address,
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.address,
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk)
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
        self.assertEqual('3ef7ae6e152e7d3c4791675cf8674189cbede49167992ad6bbb6f663e705d709', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        # z = bin2hstr(tx.signature)
        # print('"', end='')
        # for i in range(len(z)):
        #     print(z[i], end='')
        #     if (i + 1) % 64 == 0:
        #         print('" \\', end='')
        #         print('')
        #         print('"', end='')
        self.assertEqual(test_signature_TransferToken, bin2hstr(tx.signature))

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.address,
                                             token_txhash=b'000000000000000',
                                             addr_to=self.bob.address,
                                             amount=200000,
                                             fee=1,
                                             xmss_pk=self.alice.pk)

        # We must sign the tx before validation will work.
        tx.sign(self.alice)

        # We have not touched the tx: validation should pass.
        self.assertTrue(tx.validate_or_raise())

    def test_state_validate_tx(self):
        # Test balance not enough
        # Test negative tx amounts
        pass
