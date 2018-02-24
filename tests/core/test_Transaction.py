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
from tests.misc.helper import get_alice_xmss, get_bob_xmss

logger.initialize_default()

test_json_Simple = """{
  "addrFrom": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
  "fee": "1",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "transfer": {
    "addrTo": "AQKJx0zw0HzOjyZb5v+o5SU+CqziYlu+4BYRZGqb8drau2pqS9k=",
    "amount": "100"
  }
}"""

test_json_CoinBase = """{
  "addrFrom": "AQOzB2jAm1iv+ec9GF9C0GROCJD/1AXBILYDAPWUvWGoIHNZKWM=",
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg==",
  "coinbase": {
    "addrTo": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
    "amount": "90",
    "blockNumber": "1",
    "headerhash": "cbyk7G3tHwuys91Ox27qL/Y/kPtS8AG7vvGx1bntChk="
  }
}"""

test_json_Token = """{
  "addrFrom": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
  "fee": "1",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "token": {
    "symbol": "UVJM",
    "name": "UXVhbnR1bSBSZXNpc3RhbnQgTGVkZ2Vy",
    "owner": "AQMXRj3NWBtnm0dU9GxkJRJUiaKCaJTjxCpZDvtoBkUM5r9ScWw=",
    "decimals": "4",
    "initialBalances": [
      {
        "address": "AQL3xLfc/IPo5Boazr5GoFgil0K4gAsjotI/Pawm71JyB61QTks=",
        "amount": "400000000"
      },
      {
        "address": "AQKJx0zw0HzOjyZb5v+o5SU+CqziYlu+4BYRZGqb8drau2pqS9k=",
        "amount": "200000000"
      }
    ]
  }
}"""

test_json_TransferToken = """{
  "addrFrom": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
  "fee": "1",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAw",
    "addrTo": "AQKJx0zw0HzOjyZb5v+o5SU+CqziYlu+4BYRZGqb8drau2pqS9k=",
    "amount": "200000"
  }
}"""

test_signature_Simple = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                        "c5409ec2f1787f779db893cea49f71b315b70c9513a48ce96d888c1a291158bb" \
                        "0513847c2f685e3b1bf62c50c122be79b6ede372a6141861a11e5e582c11fd55" \
                        "1799ed7a6cdfd1718e6b5e93e3c59901acec7b11ceb94869862525b0fded5c24" \
                        "ff65e075a3ff536900b22e97ba324479f51b1a7cd987db85fdd76e4b25d16e19" \
                        "11d4453f54ce113a9c6f828762129290b7912e552db1b622bddc1904e7199515" \
                        "5ea7dc03c8f2622ffa4f161834244d0e84a3229a9777cdf7b7d67da1eac9d0d2" \
                        "5d3c5cfaf92f4064ca9f101e70aa41e8dca09b2fede02f6fa55fb5fec91e0c98" \
                        "9498088385a1811d054e3d083678e4223ed38901758486d4e32a21c0d179ef54" \
                        "d6aa97e967bbf1e57417ca627e92faeaff8d542d57a44bbb3fcf241fd9762c3c" \
                        "2e7a0da82fba7cac68e2d00332a428212c6771d4dd00172a181529f3d806a137" \
                        "f82fd7f8891d6f5c3c9af88913a27328bf52ee0ce74b1e90cbc51715ff44c8aa" \
                        "5327c5a36a466fd065998ddb145fa872731d126c8731d4d58065ced0f4888bbb" \
                        "91a965e8e49add621e3d9a8b08ab734055d32e51a4c4908d6433a6d5377bf5aa" \
                        "1156400b060f10f4ec80643213ed5cfaf3f64b66c585ef0eb5c6d54da3d1dc24" \
                        "1551df80c658c2a60af7760ff9e1cd97b9127660c31cad47241e643069562bfe" \
                        "0b115e033916a1b60607fb8ffb66676474a63f946e05f95aafdd960845a63ec1" \
                        "884f786cd9369c27db970dd50c0d332ceabc765b2661587a93217d4bcd4543fc" \
                        "5960aff0cad7fca00923f36ed14603cd006c598b58b8ce8601b8929ab3fcc953" \
                        "0fbb15f4e8f3d9196ac6943623456a5b8cdebb7c94eb3dc13302ac921a20194e" \
                        "f6cccaf50a56118a4b94a9235005d559ddaa83576fbd3e328d2561f9e72f1787" \
                        "da22fe9072a2156104356b8bd525e03216611c2fcc88d2f51570f85990ed6c61" \
                        "569c80d1afcd89109505dc82fabbb2d34c31297cb635c5008fea1e5f6540de26" \
                        "785bf3306cc2e95e7857260df2d9b127c0a0ea6fa8d85323c5433f35a3c6a2a1" \
                        "8ad90323383a6f5c7a29f745db9af6a9e99a6e26cd84101650d568eae1e0d77c" \
                        "3754ce72f82adc7b0d6314a2eba45872ab09987f93a28f842a122804c2a3cd45" \
                        "c62d6393d84c5876c4330107925a081ae20863dd4c76def98367fa2be61f5755" \
                        "3bcf4f04fa06a3d5b9806f7120686608d7e187387913f6a9b37adfb64cffff9e" \
                        "a18850467f807f5089ca5b8413969a0bd652c44b830909e7dde60352b3fcb5ac" \
                        "89545a5afdc927c5fb5a023bc1d00964f1a9a34f47801174c85d809cf9f7d250" \
                        "e2bbf13a87251da4bbde4d0f337e47566458efa7fb9f4e39990bc10e2c36dd37" \
                        "abad72a02eb54e05c1ffbd8196f5996c7c43d0b39e1229c4836a2e357746b3bd" \
                        "3618c594c9bc6400f7a23868b3bc3a62b69b7923d94f340888fbfaa70b3cc768" \
                        "afea51df8a75dbdbb1213c15c7614c3bbeb745bb1aa3aee2f3b272ea85394500" \
                        "a03107f1bbe54d1cd69c14803b4962f836396be2651f12b79e2a8400122ef9ce" \
                        "652b62d8ba1351ed26b9fe8947a694647c61f4af4ce02d2c396eae87e6593c20" \
                        "9bfd608a23dd2a1fc8e11ffe7594962d04906c38bba4347398760d68a3a30148" \
                        "5b457d4b00efc7325e1d9294415baed611958439d34eb9596bee83d652f493f5" \
                        "b4cbe7b3df4bcc292105c88b9e6d9cd821992d6477419721dc876cc1c7c9ab0a" \
                        "18197cfef04c4df5ef3fa50799d409cb208e9f70968c78fca32133abf3c2c383" \
                        "f62f78d6dc0926f9225788258494ec4c2625ca21bde47132c75d8464d5f2805e" \
                        "4e76364415e830315314e9b01d854418e1bc62a8ba9673df9193479fd832f2bd" \
                        "a424e2ee373ac116088c6d0d6860e7ba373056b5aba89b59419848522e538cf5" \
                        "fbb13c240d349ac447d10b74e97bc8d56c84b4173d00fc7762afdc77ce5ac4af" \
                        "7e06fc12d0a40d3e38bd2ced566c5a5001259cef33440c52fd13a8f864d63431" \
                        "2514a9dba6361606ac7a90769a034969439d5d22999074613e5fb6425359020f" \
                        "7b26b6d01111d16b5e7cf95fd4d9781ff2d156bd953add10a1608b4f38075b86" \
                        "c12a805699177853b7260a4549eb8f6278e7afd998aa5b9e03e68e76859c2d05" \
                        "e75ef40b945a3b97e3ffd50541d3298f20e3a14f581f40fe76fc8d0c01eb450a" \
                        "453eb14bbfed1232d7e0557d4592d0a8d388dc9f8a73a128867af0117222baa1" \
                        "2df9b9af834b74be91a457caf7ed080dcc947946d55a93d3bfc1ea89bc02c196" \
                        "7253b3cfda707d79e54ff7bf80cbc4f108e3f6bb3808edc82e523f54c1f8ebc5" \
                        "d89fbc0bfb141d45a75d4e9d93a65eaed3ae9aa2c2ced0dac16e68737d73d1b5" \
                        "47ac2d651be1520168382bebf670e8d04505c977265e300978ff7eab98f08575" \
                        "75d989b4243af5cc27162f234250ee382d0b8118d6c6ef9d4ed060a2eac6c2e6" \
                        "00e498ef6de0c4db4da73de282d672ce39cef1432831180dd64078bba0009511" \
                        "012895f663e269f0ba734d324a9c84ed34ca71338b68e644d18d44432e81698d" \
                        "f44ca2074011fdaabdd8b35c8b77e7e44ababb3735520b9964a5af779dafab1f" \
                        "9b46baaec62673f770b2691894193eae054652d09b63c6f85486bfcacbdfd169" \
                        "4d6b0ba65bba7fd22f6cc2f0a62dcd29a113fa27fc2ffb3210d57b36bba22e13" \
                        "173d1b71de920d4f14af68048e8d16ddadd9c49235df0e366b9bb37f19954a14" \
                        "0fd30016a23f86a5595466826fc324441864a82ef315a0ed90f448a629e545fe" \
                        "5abb70b47c0a1294946e070773ba2514a7e3dc6d8e4e9c7915ca41cf10f032df" \
                        "a5c13dff24e0b028c31de0aeb05c8de26648ea11d03ac2c8a47e677d95f4f090" \
                        "eb24c40ba2923b746740cae3f5540ddfb888c74e63284424429402bd993cfebe" \
                        "692b8c28661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                        "b3159b6107ea796cac4c62073234462b51a0659bcd44e933cc073623a3d2352d" \
                        "25bc698ea966fd6eb01782c47827ab868416bc66edff5648a3c0f2ee5cdd9b1c" \
                        "b534531b64977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                        "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                        "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                        "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                        "9548769d"

test_signature_CoinBase = "0000000b01c683d859b4f21c43e0564be6b9580356fd983f5ab2e25ec51573c2" \
                          "fb2bd5939854e491fcab92749536cc36f73cd3fa1752b3a9c48c3507dd3091a6" \
                          "a4de2b731638a121cdd0276ca3d3ba29be375b3579e552510426363bc509d8b3" \
                          "5a0cf4d038f08c7cfea8697ff9cc0d497e9c120b97919067dde0fba42f2b1b8d" \
                          "59a1ee5897b4c518768d40e110b23ebd9851adc9c060c476bac93b93a342cead" \
                          "4979fbc51060f1b8dee13580bdbd1f190b31eee2585493d5ebaf68d7fde0ebfd" \
                          "3eb00340af58e2dd4cf285f4657584533e45eefcb10550b31cd2743bdbbfca61" \
                          "00951fae296d6916fc583fc317363bb72cf1917a08ffdf6846d8e4bffb0f4ab3" \
                          "10684ffe81fccb5e8809acaf68fc0e385b3621310c4f47749fa702da1deb81d2" \
                          "503228da9358ea38e165d6971e324d02f5159ab5681f83163ba0268bc2fe42cb" \
                          "3addf93c063fa4e2032077170f12cdd2dd2fc85d3d6671f0ad692f16381565e5" \
                          "003ba446a7f6df22344cbb9342c64e49f2d54c53e4512b0822e715688dec5606" \
                          "99ff8160bc7e864404e81bab5d5ad88768634764665f48e306d9609482580489" \
                          "d852b91b51368420159c60f59245ce07a84260cf8991f3b328f4757ff624348f" \
                          "c7fc9c3a9619c3fa0c3ed3057c7c916c8436a627d981ca25cf302697ca8a4e31" \
                          "41ffb408e0646f7c4eb29c64676dfb0556c7d73c07266e022cee8be27e45eb25" \
                          "56648239a4e10b74876b727047d5ecca81d11266dfd1d417529c0b35e118ecd3" \
                          "90f13680d328fcce37d48f6b3e60f7dc047c531671f2376a46e3d1c784cc1bf0" \
                          "32b4578aebda89fee67bd441c482ee56d66f54d4269acecca1c160ec73ded879" \
                          "ee445db1aacc199964a0db3444e1e53db381509b123c8f8d3987a820ce7336db" \
                          "de11157905eeae620a4d5e4103c879f40e49f5b4b8fa1f12b6184ddcbda59af9" \
                          "300ac0492e582989b117a5cfc815d7e2f035ff1039236f1124aa389df44ba6e3" \
                          "3c846221f3eccc597f695e425016a887fb99f3aaeed8593d3ac7e21c862e51d8" \
                          "a27d79a0d3f6b131c680e6237c264887d4909b62a3b43cdb6e682bbdda34c445" \
                          "e3e73461d163eb36f6670f3095ce571d9b84e33a00c51bcaa77c90ecc66acffc" \
                          "c8ad3c187c95646e97849d944ace1fcbded0cc7464721c356c2e8ab9ba4038ce" \
                          "3970ef51ed4a7975514fd8507a63bc7806366e5114158e9f770996c7e9b12927" \
                          "fb5c43a9a57818802be660fcd34fd8340f56e0b4f1baa60e8a58c8cfe563d794" \
                          "9f25ae2bd7509c30f26562e38d71f3e15c9fd668e9a1b381a032f1e254bcf9be" \
                          "040ac15182c64a14434c218679d96f75b296eb07e6acdc02ac7ad213ff132a82" \
                          "02ad64f77b88f9a4cc866a46be9efb4e2cee655cddcc3b9e85f185d460046ab8" \
                          "343bd46290ef6827aae0081f2a76bbfc1aefdfd1b7f9a117d1031f1a3d31a14d" \
                          "41e7f19c00566e82ca1f46b65531d3f56da13f6e9c58aa5080cc9b7d7519187d" \
                          "5a0eb157f396b12366cbc8ac419904457a7e79a117499eb10c87782249e22197" \
                          "0af4d8bf01143ee5584099b35743679ce2e92bfd9343453a38b0d34ec58cc77c" \
                          "45b01847206afc248436863b47a05e50a574ad5797a3658ba7266d2d3f489121" \
                          "e6b6937b1135415193cd387cc92e4b3839413c21ab16f65d0d116d47258afca6" \
                          "f00f436d7c08d9f0dde18f81bb154a12c188274f23c13cd3889ad12368f5cf6a" \
                          "9f24321d737f731922c51a6de529709065480978e0872832a6caca348e43eb9f" \
                          "184b457c1136b22f292b600053854f431c88f60e3926a8c9852c266d42db845e" \
                          "2906333b77ef85b511f916ae5c41a28fdc72d653418a19bd69d1fe1897763694" \
                          "61f55339de339bfaff23eb3d44299993a2f01af683c2f9f10768540b70b90079" \
                          "01190fb902c1d233c9f7ba751ce0b49fcacac1f423ad9708d1d941f48fc8cd03" \
                          "f6426b18b8e92cf107f01a949c7c1aaf889051e29e857db722a86dc2776c25ed" \
                          "928f82f89d555bfc0aa0a546ef34dcf24e0af7825dfd163eceba2a95d5d97f3c" \
                          "31b96ec7b8f0e59a310e798c4f7a741b7b0a5f7c36fee181b5d600e0bddd6d4f" \
                          "dd24bff944451a0c1a2661af0b41673373dccb917bf8442bbbc92a9374523221" \
                          "cf96cb349ef5525549b45cf50f576a1d861422b544326ec78060b3cbfd02b0d5" \
                          "0898cfac044e52a8a7d77396f198b9f49e5e71fa9de9592eca25694ca1e8e9f3" \
                          "82c37cdd3c66a06c7e3394734cf3e721fea00268b61ad28cd23cb214b0fa1cbf" \
                          "5804b752d3ec3ee986bc5b25930503c8f80f6c1216f2e55e4a77a697c791f806" \
                          "fd51f8f61351084ffcd20ed47ebf81b11764d0ab8e745a627ff8cea80120d773" \
                          "48e4a9237d6598a76a2c706a612d0f26533eac277b0983b54f36ee6f9250e697" \
                          "7725edf59c369e4fe48353b359d7ecf1c98e20feca7e86f32692147cff262951" \
                          "796f588d65416a2c43c6ee52c68de92c91b599e431a4529acfb57274eb245cbc" \
                          "9023f7e15b30633b5f7cbd688900698c7b38bea672c2309d5db3f61cf4b0728b" \
                          "668522478a061e2949c98196ad23f8edb9fa4ed65ba9520c4d62074b573270d2" \
                          "7b2d757a8411c793870f864c710e6821e2169d0a50e639f0cc4679887fbb71db" \
                          "7692d679c664aa0d0797877b069ea7e7194f3dce522e09b2a246e5a8a06df60b" \
                          "447f2998eae81e5b83597fa121d74de081411b51755cc8ebf14ff45f313e811e" \
                          "a510bc2b27c7a7083492267fafa06451db9f0ae211dbb5476ff467c2a4257551" \
                          "4fc8a705f0a399f37abf6d856b5ad8d8853c8765496f976b32011a65f85b5f44" \
                          "0131d431e0fad906ab5ac37f15399f26586249bf6eb9c30c1dac896ae230bf8a" \
                          "5283e1ce93d7f80338283dc4959014caa3cd4b757d58592297f784d3db35f125" \
                          "4b05ccd5034c65b0ceb2454324840c6ec607ae41945850f74bebdf5245ddaae0" \
                          "03c48033ec9f46d51f5f290c180b387866e1bb965ba8d81b85a8bcb249f93cb2" \
                          "a3ad1f123c11a18e79884b5f82437a76e69a6b5742021fd7d251e95b7bc38335" \
                          "8cee6e7dbd3e2ef740aecb51b3847074d1587c82bff5091700520c71ef553703" \
                          "9f105ddc02a5287e14dff7ad53c21e16b62a15b2955584682c2aacf784908653" \
                          "f731168d90b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                          "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                          "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                          "9548769d"

test_signature_Token = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                       "c5409ec27eb9574582e0bff48d8f3b589c42d4228ef0a8d4f59d38e47ceda60f" \
                       "167adce84f295a394b19918853143fabe9b3195ede3bfd5d81710df5e765bdef" \
                       "7f3674f58d3961ca3a9dde367280c13e21bc2750b586186cca88c39ccda7cf14" \
                       "21936ce98e035bcd1c4522491e7e42a501c144d83fa35494985820e6e7abffc3" \
                       "8d8ad448754994c15a37e1e7100770d34768ba43481134c4bebfa2eea2f1533e" \
                       "c8839e174d7841bd8d3ed570ec07f30d72c9d00288e2e0a84a21625d45b2ce6a" \
                       "10acda4afac78ee0556dbe2d3dcb07f0331c62d6ba58d231a2207416a2e4d72a" \
                       "2eb063473ab3aec6e163323098d526ad6aba14815904e2217123849e7dd55d42" \
                       "cf0f740ea77a03ecc2911e912168a072e222a3b4a4f6267124d13cd0181b115d" \
                       "2518df4f2245194ca27650363fc0a0e29f180b5b134563df13a99bfcc1270bb8" \
                       "408122c8a0b48abe3d03da946dbe7672004a2fe006eb60107bdb2cd3db3f0956" \
                       "87a5e4d46a466fd065998ddb145fa872731d126c8731d4d58065ced0f4888bbb" \
                       "91a965e827d9c81b5f57f36c7778b248143242a46d0ec00c7efc12b9e958f175" \
                       "e3642e6343ba177846dec8b5bf3961ef1ed0138800b7451432f4cb8e163c19c0" \
                       "13f465eae07af2df97419bb46a8017f83c5ba3c11efc7e6df17c1ee793834737" \
                       "2d3686f4a92e4b61332c43c81ca94660bde1b6df102fd75537087354fa342389" \
                       "5e87d96ed9369c27db970dd50c0d332ceabc765b2661587a93217d4bcd4543fc" \
                       "5960aff08202028f7ac47e8aa48f945f0df4e889dca508cce708be5603220f4e" \
                       "e9029860cb1c3166d0ad5a5ff288a96bf8705efa542cdd53477f42923b8e1977" \
                       "0d7a4938481e24dc9c76fb68de25ab3f68c92285e79b85ad591636c0933e92a7" \
                       "e5458c5ba0d0f361bfed2ebaaa9e5480a31989c63e7718736739a51a837b70e3" \
                       "d995e2292587c98ca4552d89ddb0549c66e7ec96a33af1c92aec54e50a82ae19" \
                       "0751564776c989a29a2ca8997746424888e7642604f56e681326100fda7d1c90" \
                       "914c526671ac0d5cf32569b0d069178d7e93cb25e40801faf8ed48e225d63397" \
                       "15f3ae10cdfcc4cef095595c54349f939579158d876a872fd6cd988858b68271" \
                       "779c13cf0410fe68e884a43e4386870dfef3194022ba3b416026aaf39609f7ce" \
                       "43bd8df4d1cff192412d5b8b14e32e1fedf304b7f66244fcd946f25740d57f41" \
                       "1a877eefba711dcbd5236bac6c202c273766f1d415279ed61d6963a8de198a46" \
                       "a06ee6a254ccfd2d099899822d0d4d325dd0fb986b0d15adbc54d6314834ba6d" \
                       "c13a420cad343a49c3f30d321f03b43929581fc4e63316b7feb210e8f305c7b5" \
                       "de390f80c764c66c40e98c06bf80a809955789506c3da1f9cfe4426c78860990" \
                       "d3332947f15fb498b2fda89cfc0434174f35013ee2b8f5abe15b4f8e8d3e5c49" \
                       "8ebedb000596e28636c8ce8123dc02ab6aba67604ebdf7e9b2296d1ae92e51c0" \
                       "dc6ae37001efba9fd0e33fb3b832411b8a249b53731ba1570a2511b737169551" \
                       "1d10e3efcb1c7249518bdd624fc90dbda70100d6e38f065c6609a0183405b810" \
                       "0b1966d5c6c4cc8c74de897e9d8e3a8cc608b43076b4ed8997aef599f18a6627" \
                       "cb63d61dbd628dde7ab75a8278649e5d1ffac5fce7f823ece8be83debbbc9bdc" \
                       "9a76f33b78e6e11c25ad67676868c05b5a83c44b9a928e31d6e36ce30f70c1a9" \
                       "b2643c51c6e5760a6f793a4942ddbf4ea7302394b283b946ca31b87268ddffd3" \
                       "575e37fcb17cce5fb9480c41c58b2ab29ff5d0a1bc49bdf3072d7db375a88198" \
                       "b241ca4515e830315314e9b01d854418e1bc62a8ba9673df9193479fd832f2bd" \
                       "a424e2ee3d04d3d4940370c77f075422e1207129762083586866b065c56e5836" \
                       "e788bfa20ca00723c8a9b3f35a8f4832db8c1c3892085f539392099cd624a225" \
                       "90bcd707121c1ac7f098cffb40e13267c8a948db277a16f4a4a06fd2f8f64a7f" \
                       "1d5d68b133018d20071bb5249105826438a542a4a51f09b64f73dcd7e7f25213" \
                       "c8a3b9eb844362563a05106e1eaf9a2c946df8563da03ee006451fc8eb59e05c" \
                       "3fc29034d057338d36078c9b7fdb4d126c42baf025dc180ddf08ce0e7b910e25" \
                       "f62c237606906750834294141d4cb54c4bb6d070a13b25c5d9837b703b6a3a07" \
                       "0c1134c5da843186e603b73c4dbdb16393557a2dd8db557a568f373b518f7c3d" \
                       "072cccc32d794129f75a7eefa95ca30d72fe62fcdcc4010315359a2945e49c51" \
                       "78aa97e963be059499f1d3dddc912c3afb8ec5157fa81f8719de919d8edf0cc9" \
                       "5e21223cb28a62b92bbf62ff80b719f46a473f82601ea6ecf64765e18aaa7712" \
                       "9480c5fb52793e8815ea8d837b62875db73e20b1d9f6c5f9477f2fc66cca0677" \
                       "9f87f35c43270d91fed7c615e024338c83c134125c64e921f1d0c3df7698a257" \
                       "0e3024f8a980dd2a61cd847b60a49f6aa7fe2198693d83c53370aa01c531ba68" \
                       "e196d4ed2916b9226cc1719e444dee78eb16052533b5a22543ad5794af9150f8" \
                       "a78f64e6dac8113aa18a3e515340035ff6b6cff0fa7a22cac731f12ec9e30def" \
                       "dc598024fa14aeddd4722f703c43c8e7bb18e59645c41b056d66eda5f4bae35d" \
                       "c229b8638aca1752a96395f438b1303e49215039e8024c84f8b3c3888d338123" \
                       "1ddbc54da7f7d5573ae953fa43edfb09baa911d0bdeda91261d0aa4d1b8ad738" \
                       "76fc072082be6489148a82e8732d581fc342fa755fc13eed42116cff9317e4b2" \
                       "db6500db7c0a1294946e070773ba2514a7e3dc6d8e4e9c7915ca41cf10f032df" \
                       "a5c13dff3f450ce4c4d21c45acff7372645b8ead1c68d58a2e1497a88a3bd27d" \
                       "3150e1c370aaee98e8bcbb0ea8105d5af302f6e05318fd7a1f607a152f2f03f7" \
                       "85850ce5661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                       "b3159b61a50ca750edfec90e131267a7617a67598832dab5906216e6ed522cfa" \
                       "4dd8ad8da20ea03c4ca1fa563b24c2d2dff64b61f648a6a827432938f60d6b0d" \
                       "e7c75ccb64977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                       "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                       "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                       "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                       "9548769d"

test_signature_TransferToken = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                               "c5409ec29c0aa9aa618b4c8297df4d3f96c453524589853260667b99d17c7354" \
                               "ad9f54094f295a394b19918853143fabe9b3195ede3bfd5d81710df5e765bdef" \
                               "7f3674f5dd538aad6c183a6c232aa9e899b669cc3422fdff1dcf56de6696aef2" \
                               "9443016f45f5947ec4f157b1ba6633d1661f34fac856e632fc5a762836cda764" \
                               "0946c385d349c00369afeb56db2efcc3590c3773814f8472f3c4efdbde2d51e0" \
                               "6867219b32b57a7bf5a0e5bdc3c8ae053df6b1950e22b82d575651cc85618dab" \
                               "5254768fcd3f84ac96747746d0435545463e4f7762896adf8a4be0bc0cd17b51" \
                               "97e10e3f888361824f04dd53806d09f373f9657e8f13617e6415f9f746e84df9" \
                               "630fece3b1a2bf05a24c0e47c425d3acd060eae3156cae0c8fe2fa63e93b08e9" \
                               "a6fca061400d2d5698e40ebef7a17641a835f46e2916216e2929772b1e7e8f7e" \
                               "dc111080a0b48abe3d03da946dbe7672004a2fe006eb60107bdb2cd3db3f0956" \
                               "87a5e4d4fc3bb9eb9e77363bb0d7fcf344ba8b07fdb83b688713753a26bda80f" \
                               "783c0ac298c4a87b61ffb23af6bbc556d866cd63db98eaca498d7c4912015cd9" \
                               "ae27182df1e77a2f35f160b208bd7d3df547a1fd872bd18359261d2a9c5901e1" \
                               "a28cc901c658c2a60af7760ff9e1cd97b9127660c31cad47241e643069562bfe" \
                               "0b115e0307bae51abf62abadd152da4eea080af17f1190ed1dca654278690851" \
                               "8a44971a1687c98c79e5f3bb9684d73a63fa3e111fb7275f898dd71d78e0e3af" \
                               "a066a3de65b4c3479da9eead4f4dfb56a76012d0e19d0eb34a3719be09be9aa5" \
                               "47251dc178cbe83ed52335c5fab03660c6d6a385bf454c45541f7e20ca9c49dc" \
                               "32990ee86fb31772c7745bfb8c46649189d9bb5e065ae21b468f21f3eae64077" \
                               "776ad299bf2e4792d7125690b95fad49e26ac02e16ab23dd474de0d9173ca787" \
                               "b95719ef00b9ca97889cd78082051f76e92f6ba81462c0ddae5c22c71bc33cad" \
                               "3581f03476c989a29a2ca8997746424888e7642604f56e681326100fda7d1c90" \
                               "914c5266435f7ef80371f11fcaec1247d9d3c91dbfb8a38dd86d0562c9160e67" \
                               "044b3295f7c5b38219516bc81c4a7b30cc5085bb09984b3c64a0deb8a730b03e" \
                               "c0585df8c511cc2fae15c93536e5176060642fa2e110d828206b49b5930b68b5" \
                               "c42100c99318591be83339c5afc106c81c2e11360708a618db848908f5817b8f" \
                               "825039540e89420363f8fc7c5a0df65d933441a3624c713fcd978d30e2df9796" \
                               "16b52c7f54ccfd2d099899822d0d4d325dd0fb986b0d15adbc54d6314834ba6d" \
                               "c13a420cc24a7b1714b5af52aa2255e1f953ce9935b5fddd2c6c3b5e036c4144" \
                               "3c320eb2016ee380fc32f8c6145c86b1b43d26ceaf9f1dd270db8d6ba865c7e4" \
                               "d90bf8e31931c5abe79736bd9d769aa855b288fc7851481e43c46e36253779f9" \
                               "c19860eae59026a31d61f293b85c1bcdd96cf08c4368e741203f53a71cc6c34a" \
                               "00b66014ac28ddcf2ac6791da03a6b187bd139d3a0e130fa68c844a4389a80f7" \
                               "0a9da89667189f0e9db4bf8c947fecaac1d35ad53c64973068cd8cf237045fba" \
                               "b384fbb0a96f837f8ea955a3b28299e5a92d1bef2d0a9852ecbe92501c1acd6c" \
                               "380218ec16308e1f3e2dbfff61e42e534b317b0054018a457cf4e9945f66975f" \
                               "bfb4ae5c019b522d193213b8c7d0de539781db36f13057037edb865c131eb678" \
                               "098ee7d7e9a3968291c244f7aa30a2de08b43306d7d4f4fab347583994ccfd9b" \
                               "69b74c2ab5f6e2f69ef368630d9ab1e18a27a11689981ea66b32cff92f37c339" \
                               "4ddb484530f3a0087dcd5cde80b3fa0eee653553859d37f864cda79bb2a61bf0" \
                               "78c729c2dfeffe09a5f588c215005bf3376e30620d0c54cc535f1fa76c2264d1" \
                               "150114a609facf9e1bfa5d43407517037447563bcdc5283e6c6ae0843309d082" \
                               "8414989b5060d39acaa9f8aa6386568c790cb9c845d19a724095cf54a6a8e361" \
                               "d7beaa2427407c096eddb0efd0bcd795fee2007d449538edf5701632cd8de827" \
                               "4f8ac66e5a87ada1616a0c94452570c36217b69561cdbb097490cc1ac17fdc7f" \
                               "624d6ab1ab30a4a3dfe3c9e70e04b8479472be1f6ae8da905af3d67af6111688" \
                               "64d22d72ef6febc299a3dccf2419fbb8246c0e15dc1c7b68c2317ea3cf1e0121" \
                               "4c8ff01bb2e96e82a10ac423d92d5fcebd5b566b68d0c78a68ae36d18fb6d427" \
                               "c24cad347453b8302acc7343bbf2201e7af11866fa5ece7f60fe2d5aaa495ad3" \
                               "b57c5d91b58ce8eb24a8eb5bcba24f8826550d395178f528df9e433dfc008430" \
                               "febaad5491eb8146a8d0fbb32fa341ee57d265224424aaef5c713d453306ced4" \
                               "536db427e04451dc030f2b83f2b62b1cd04472033185d9bb1bb8066d70940c36" \
                               "319380f0839d8db5825ac1b168d95a474d127f6488d4d2378cefe1c6efbca67b" \
                               "22a51ac504fc9c78cad7f97cd99bfd37a739a91714cbd03e9df018790feeffc5" \
                               "69b654ea4bbcd37029427ad873e101fdc06e48b7a07f7f436025d5b5419b13d1" \
                               "6da3987f6d5aec6d309a5c3970c8ef6b9958d1a828f6b1c85d60467ebf50fe08" \
                               "2f117eeb111ad85842e2cf69e19dffcb459c7088671765e6fd64d5a63b8c383b" \
                               "b84d668a26addd4e69be8ce84cee6dc0be18374f8958adeb6f28bf7167e46542" \
                               "e166673f180472a25b74247041c13040a8936194d7f05e797a94ba3078a014a3" \
                               "c2f8b2ab97f7c42b1625e50209fd5f9fb225e983993a0648a078e09e024e2b42" \
                               "71d9c8b27c0a1294946e070773ba2514a7e3dc6d8e4e9c7915ca41cf10f032df" \
                               "a5c13dfffb413f0d2d6845d7d72d16e05260435024dc6d0c4f41a6d966813b42" \
                               "e590bb5870aaee98e8bcbb0ea8105d5af302f6e05318fd7a1f607a152f2f03f7" \
                               "85850ce5661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                               "b3159b613be8d44a70ed4ec18438a3f6551ce0a3b1bba00397b11a0e99ba66f5" \
                               "cc483cadf640d9b0c281e8105bce9810804b9d1da640677c0b591fcffca5f994" \
                               "3382811d64977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
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
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

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

        # Test that common Transaction components were copied over.
        self.assertEqual(0, tx.nonce)
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207ad504e4b',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab'
                         '77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual('bed7e934478e819c2586951a3e86a912b9aba45e02fba27ff57ff3032046186a', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        # z = bin2hstr(tx.signature)
        # print('"', end='')
        # for i in range(len(z)):
        #     print(z[i], end='')
        #     if (i + 1) % 64 == 0:
        #         print('" \\', end='')
        #         print('')
        #         print('"', end='')

        self.assertEqual(test_signature_Simple, bin2hstr(tx.signature))

        # Test that specific content was copied over.
        self.assertEqual('010289c74cf0d07cce8f265be6ffa8e5253e0aace2625bbee01611646a9bf1dadabb6a6a4bd9',
                         bin2hstr(tx.txto))
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

        self.alice = get_alice_xmss()
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
        self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f',
                         bin2hstr(tx.txto))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)

        self.assertEqual(test_signature_CoinBase, bin2hstr(tx.signature))

        self.assertEqual('ffd7f37342d51d9cb45fceb5a5e13b2b93b7cf8f78f343a264547b6cd50eafe6', bin2hstr(tx.txhash))

        # Test that specific content was copied over.
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207ad504e4b',
                         bin2hstr(tx.txto))
        self.assertEqual(tx.amount, 90)


class TestTokenTransaction(TestCase):

    def __init__(self, *args, **kwargs):
        super(TestTokenTransaction, self).__init__(*args, **kwargs)
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

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
                                     owner=b'\x01\x03\x17F=\xcdX\x1bg\x9bGT\xf4ld%\x12T\x89\xa2\x82h\x94\xe3\xc4*Y\x0e\xfbh\x06E\x0c\xe6\xbfRql',
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
                                    owner=b'\x01\x03\x17F=\xcdX\x1bg\x9bGT\xf4ld%\x12T\x89\xa2\x82h\x94\xe3\xc4*Y\x0e\xfbh\x06E\x0c\xe6\xbfRql',
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
                                     owner=b'\x01\x03\x17F=\xcdX\x1bg\x9bGT\xf4ld%\x12T\x89\xa2\x82h\x94\xe3\xc4*Y\x0e\xfbh\x06E\x0c\xe6\xbfRql',
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

        # Test that common Transaction components were copied over.
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207ad504e4b',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4'
                         'ab77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'QRL', tx.symbol)
        self.assertEqual(b'Quantum Resistant Ledger', tx.name)
        self.assertEqual('010317463dcd581b679b4754f46c6425125489a2826894e3c42a590efb6806450ce6bf52716c',
                         bin2hstr(tx.owner))
        self.assertEqual('ff85662a63aea954aec905da5410df48de6ab38c3e0065e587d8dbf4a0b72008', bin2hstr(tx.txhash))
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
                                     owner=b'\x01\x03\x17F=\xcdX\x1bg\x9bGT\xf4ld%\x12T\x89\xa2\x82h\x94\xe3\xc4*Y\x0e\xfbh\x06E\x0c\xe6\xbfRql',
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
        self.alice = get_alice_xmss()
        self.bob = get_bob_xmss()

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

        # Test that common Transaction components were copied over.
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207ad504e4b',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab'
                         '77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.amount)
        self.assertEqual('558e4224414d9922c05077d70c119b0f8b0595831372fff1c881d504163fc221', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

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
