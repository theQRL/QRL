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
  "addrFrom": "AQL3xLfc/IPo5Boazr5GoFgil0K4gAsjotI/Pawm71JyB6h0/tw=",
  "fee": "1",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "transfer": {
    "addrTo": "AQKJx0zw0HzOjyZb5v+o5SU+CqziYlu+4BYRZGqb8drau4+8n2I=",
    "amount": "100"
  }
}"""

test_json_CoinBase = """{
  "type": "COINBASE",
  "addrFrom": "AQOzB2jAm1iv+ec9GF9C0GROCJD/1AXBILYDAPWUvWGoIHNZKWM=",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "coinbase": {
    "addrTo": "AQL3xLfc/IPo5Boazr5GoFgil0K4gAsjotI/Pawm71JyB6h0/tw=",
    "amount": "90",
    "blockNumber": "1",
    "headerhash": "cbyk7G3tHwuys91Ox27qL/Y/kPtS8AG7vvGx1bntChk="
  }
}"""

test_json_Token = """{
  "type": "TOKEN",
  "addrFrom": "AQL3xLfc/IPo5Boazr5GoFgil0K4gAsjotI/Pawm71JyB6h0/tw=",
  "fee": "1",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "token": {
    "symbol": "UVJM",
    "name": "UXVhbnR1bSBSZXNpc3RhbnQgTGVkZ2Vy",
    "owner": "AQMXRj3NWBtnm0dU9GxkJRJUiaKCaJTjxCpZDvtoBkUM5r9ScWw=",
    "decimals": "4",
    "initialBalances": [
      {
        "address": "AQL3xLfc/IPo5Boazr5GoFgil0K4gAsjotI/Pawm71JyB6h0/tw=",
        "amount": "400000000"
      },
      {
        "address": "AQKJx0zw0HzOjyZb5v+o5SU+CqziYlu+4BYRZGqb8drau4+8n2I=",
        "amount": "200000000"
      }
    ]
  }
}"""

test_json_TransferToken = """{
  "type": "TRANSFERTOKEN",
  "addrFrom": "AQL3xLfc/IPo5Boazr5GoFgil0K4gAsjotI/Pawm71JyB6h0/tw=",
  "fee": "1",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAw",
    "addrTo": "AQKJx0zw0HzOjyZb5v+o5SU+CqziYlu+4BYRZGqb8drau4+8n2I=",
    "amount": "200000"
  }
}"""

test_signature_Simple = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                        "c5409ec29323bb32ca19a421c56490c875c9e6a9c6e2f3dc8fd918f85730d802" \
                        "b5981f68562690950fd6c1a1db05ae6f331ebb4c463d99b07ca25f2211b89e61" \
                        "95b06005762533496a7b8718b7596e472e31670f083b435300569c56366538b3" \
                        "93d6799e9067b58cfc2e97aa376c26ed4d3aff11a1ff8e9815d065d85154c209" \
                        "c5b5787aeb6e88d51c853b4121d0cd731dfc9211327e78670edeca78173935e3" \
                        "aa1a4171753209750f0acf087af3a2e545a9db00e615ed8118790fd8707d68d2" \
                        "922899426a83ebcaf1418846ab3fadb71c39a24d18bbf7b64afa71f0a8f109fb" \
                        "edf702feb6ee05d9c6cbc85b254c0fce9e410c1b090f954800ba94d47b0631a2" \
                        "ab7e7ed1a6e24e0cb9debe093e528b6619863a7cfb11c80e0d0122b9851e55ee" \
                        "07bef01364d70f8aefaa9488044eac2077cd43d2b2f25c7e704ec61e034a6cbb" \
                        "bb5dd70ba5e64ccead136b174c496eb8f7083d00c825ecffba2d40798ccd7cfe" \
                        "62ea7b8521142ff61c1e2c70ef7a6d4cc1788397aba708efaf668a6c7ea435f2" \
                        "7bd6c7d7e038bfbb1707bf3b6a73cad7f1362bc7991c8fb8e933f2e5163f5944" \
                        "7fce58f489b943189be7754384c2727561e3043d0871eb5424cd80afea471ca7" \
                        "c46e3d39e07af2df97419bb46a8017f83c5ba3c11efc7e6df17c1ee793834737" \
                        "2d3686f43916a1b60607fb8ffb66676474a63f946e05f95aafdd960845a63ec1" \
                        "884f786cf05ee12e6a9f58d51adfa8d2131f5455e9fba4846ff636363423a2d4" \
                        "ea5752ce2016734cbd867f53860a538322461092b333182dd53370219ad023d5" \
                        "73a85fb4253aa57c379c1ea03406d9e86082e3758656659d153903bdfd3e2eaf" \
                        "8fd0e8776fb31772c7745bfb8c46649189d9bb5e065ae21b468f21f3eae64077" \
                        "776ad299d2c7db4c76e2211476b293270f9985b84b8dbc4aefe48d52ab98c0df" \
                        "0bc93fb5d3f301e52124357785ad64cf0ed20d190fdc022a42ce090d0bbcd779" \
                        "5429e2689e57218c6c28ad647fc8ff729efee23cb91d62594481613483f6072d" \
                        "c9994b4f4a4ef7b9d5777713f42aff893335e75c2bbd2c2b2a6cc3ae16e31a74" \
                        "47f033016051cd153c2f51af21a57b013240feb6943345ccc55fe7acf72b280e" \
                        "1ecb435977a61c94f9555a29d8d87fbd09e0937fd78048c1433ed8dfce7881fc" \
                        "0708e4479318591be83339c5afc106c81c2e11360708a618db848908f5817b8f" \
                        "82503954da14e980a6e7acf49782c5b3b4b4493f35780a3e37ba5f3632033925" \
                        "76634c4b04ad21c70492c3afb1e85e0a02656cfc9765d8e65f98063fa4d02a22" \
                        "e36aeab50dc8ddaf45941d0af4a1b0972e7ee279d76a4291a3131939fe6c0a73" \
                        "a4289cf4366eb7c300817d131e1e5d77242d3c917eafe1d0e5b12c05859b5ae3" \
                        "bdefdaf2cc302d999883db320df19eba06cccc9299a53f0ee7385ae03461131d" \
                        "a5131a7ca658fbd5584c2aafd0279cd13ab5d8700980d496de10003276cbbbc6" \
                        "e9a7c8b2e371aa51b112fce4eaaf8c84ab44a6d24c5748d511f1cb1dacf09097" \
                        "1861bbbdcc39c1707c3c3daefab57d4df8db0a27f2e87b6067565c2f81fc734f" \
                        "a69cc938ea01f6fd651007d2017b861d3a625eb4c71835666728e4d63345352f" \
                        "17ff60c8c1d6f538a839b25aef6bd168187c1eea6f7a27c57485655b25b7eddf" \
                        "eeff8bfe22499634d677af73c3fa3d7c8a235ae0a947a7d49cdf977d70a692c3" \
                        "563d4165126341de8d6c7b8b09a76b53fba28267b698e4327f519231628f59ae" \
                        "ce917f027e38b972ee61930c58c5a489d44f952a513b6e41774af6ba37cb6e85" \
                        "2d34a912faa48f72acc671384704f82b1b6a60b72e003af844640e731061341f" \
                        "0c4d03051d1142fb4a66afa7dc6afe01e385bb35d324ac0513c63cb365efe1b0" \
                        "b8c870f41c5aa004f4720106d9a6efacf3ed109f15911480e17cecea629a5d06" \
                        "88bcec8e51b1fe29037658c82a793c8c27cbb128cf68d868cb8fd7ea2d0f833d" \
                        "2b86e4e5c3c1dbdb0031231f3a4739a1589cd6052b896115b4087acf06d35e2b" \
                        "649b5f5e00b2331c814d0226ed6fb7e6fe948fe2ffb593cdced2b158d1431021" \
                        "701ce627a789371d93302e853a09ecfdee53ba2188f2e6df83dbd0168ebb261f" \
                        "0fa675f6c2aabba772a8141b09c75e1626fc27f6b8dafd00de7647fc1f2badb3" \
                        "fabefe7fb2e96e82a10ac423d92d5fcebd5b566b68d0c78a68ae36d18fb6d427" \
                        "c24cad34d7d89a98ce39d1d767925a6686c30e204d716758c3cae305698a309e" \
                        "4cdeeab7cac8dd5ccba4e52f005fcbad06899172f1049e1f6473a136a3b913a2" \
                        "bf6c261123500d2325e3fce1f3cb1b8692034febca736f68e2d8ee7272ccb828" \
                        "78db9011f9b8891e909f93a75da72541ccddf1424d49db9fb2995380c42c23cc" \
                        "858e2419bf146af412e4d2730e2df9a972e56933a37d332724f27fcfc248c7cd" \
                        "b6ebc0c1f38fdc31eb3fe789e611d47b450dc50f790420833f28321c06188dcb" \
                        "2269c9b3525e9c82815c7061065a06994fc2cc66b6e99f9ff2c2d0175ab5127b" \
                        "43eb43c7868f2ad2dbd956aabfe09e6571dca863c5bd2b6a4eff42588e220c9a" \
                        "5b24c8b15786e16cf0f6ad9fda0529bbec4a2898219b208b119b9e572120a8fe" \
                        "de7465a985930e806d8c6e089bd1a550021132ff35e23dcc60307b9980e0ba25" \
                        "b18e2575180472a25b74247041c13040a8936194d7f05e797a94ba3078a014a3" \
                        "c2f8b2aba23f86a5595466826fc324441864a82ef315a0ed90f448a629e545fe" \
                        "5abb70b45ae8bb80287c850ed40ee07964e701c76d921af0cd46a28f8b797a3f" \
                        "046de3faac5ddb4418b12c18da0961e3b2fa78cfcbad66b1032c19bebe0a2190" \
                        "4ca2a2c0ce8b86c5c9be8c000c7f6750b008535742c64afbd5ff057ec3827026" \
                        "46b999a5661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                        "b3159b6137c346524a62c6016019f994320db4d29b98965fe56bc26bed44a556" \
                        "3fafe98f7ef5bfabc6b2c8d9ddad1af6d182e69f513fa08737e67b8a9fbe1219" \
                        "5566130764977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                        "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                        "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                        "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                        "9548769d"

test_signature_CoinBase = "0000000b01c683d859b4f21c43e0564be6b9580356fd983f5ab2e25ec51573c2" \
                          "fb2bd593c511ce589898af317eccd948bfc9974c699473547048342fb6c933d5" \
                          "cdf8f37688b7b4178b59b01a4ed2d95da64599617c6ed08ce4b20adfc11502be" \
                          "5ace9fabaf1ea9f43dc96b034e4ea06176033e2342e1ad2acc798b08bd931e48" \
                          "fe27fb527a60a0d2172fb9b4e4de402f860dc71ea304d2da97cddb28a7f60f90" \
                          "3997075356ecbd4a15ece78c9dee7087a778c4b80016e135771b8763aebe7e3b" \
                          "bdaea1fb0d6fdeb42222e414cbecdc322903c8a44a1243b6a4748731a1355823" \
                          "466fd4a7a039ea4ab96ef9c3952a31e1053d9505b1a7881a276a8a1c516b4c0c" \
                          "09a0a6c8852526e9108d750793677080189d22a2d57fbfa27249b42d1676f4b0" \
                          "afb0579e81d922e2f366154ec2bd278ac26b72046a12505011b299b047c440d5" \
                          "3e588c8ed221105845ba30c8a79807421c9dfcfe1913142074e9b1fa94ce6c16" \
                          "20a52a0cbe7049f9669b687095f165fcbd62e1056522a722205f1f0a24a3ef14" \
                          "e9fc6c7dca467f3a72574b14a0b558c73ce2c4ef84c76fc5ff3d1a7c2d5381c2" \
                          "eb61af94e0ba63d7127c7ae4b275e2f9cf2080426c5e6675d962f5ad41342544" \
                          "fe183f403964a20403c146d2f21c951b7a6363deeed65f69c82c256477c5a2cc" \
                          "219b6201b3ffd57317c6b9d6b88f51bc448d7378079b31bffb12684d19ee13bd" \
                          "2f2ee001420b517bf085f44fd8302399a522e7f2000d039210e3f1bf24822c07" \
                          "967f7da249a77570ad3bd64fa31cad633addaf84a797757576c82a97a61e4a1b" \
                          "ae725cda79efa88e5c7d29f68fa310bd65b8546faa5bc82329aade71c6808150" \
                          "e6e89d4502d4398dbc8a38b1bef383b3373d4b4d49830e10dc404c9b1f78c23b" \
                          "18fd2d9a255df6cb7b5fc05481e7775ea0513515ce41676fa6ba9e33d69343ec" \
                          "ca13c491e443879cd8eeab949b3e273cff5a569c36cf97641bc6e7fee154c52f" \
                          "ed6367af177b837d48b7dd1ca2ff963057730034ea30656cb3efbd060ef938f9" \
                          "60cc0883d3f6b131c680e6237c264887d4909b62a3b43cdb6e682bbdda34c445" \
                          "e3e7346194e8d3e9c6b741b72ef56139912b89d851ec18a8289fd24d0e44ba33" \
                          "970e6fdb11934835496e90e7c0ceee8e5a2077b2456e9a13ceceb563ba3b8572" \
                          "1839d2662a02219d5d2b341422156cfb5215e4455d56780f58bcd158ebd1dba3" \
                          "48dd7d03bebc66dfbb80b0251f7d697abe394c46838b32629ed231633bb25160" \
                          "e63628b68c1a56403aebfea205f94c74cc7b843c466b71806fed1b9fa089d262" \
                          "28c71edffac77921407fb6093da44bb8968284ece1b7661994d074d29098a887" \
                          "7ece6fcd541e25d5acbcb47355b40f95605a9f9253e83d72b86977b70feb9e86" \
                          "01723e0a1b85ef5e6aedac911e115876d58a3f0447bba0956090bf95801bd591" \
                          "dffaaf6b192472c6d25eb7d776f97f0b9e149673bc3eba1e435cb512710088cf" \
                          "b83289f8891e80860b852f27c9a81571c2c06cc07effe8fb96de5e74dc42cff6" \
                          "9186438a092db3b805a29d8b4f6b77f8835a1523b24a409e511398a40bd9f17d" \
                          "b4ee268bfa324b56708dbfb5dc0519588200712b2f4d6f8c2f0d83d41195507e" \
                          "393a126fd72639715fab1dd7ca3fd0a7f0a043362bca4231133520d27ebaa712" \
                          "a22a16c2cfaaef227329bfab38c232e79622795e9f47924fc02169ce2ab19dc4" \
                          "f6df6f0a9bbd8ede75bd2d6ec10b228af91534787c6b262ee8c261e1bed6dac4" \
                          "5862aa9fd1990060ec49d988bbbfb99c6464088f21fd8e152af7128c70f897e7" \
                          "2f741ca0d05b280e9f3be942fe47d0471a1d34635b2b38c45d9e0da8615ed593" \
                          "3ccdc458527be73ed56422b843bee5365f518b1dcdd1eee24631aff4b022793f" \
                          "11f572e6ffb9b7c616ba14a6dfaae8b08e8cbe040ad350173d898b9fcbffed9a" \
                          "3e842cc1c7ef753495ea0fe34e5d85c26bf1305aa032c3aa4f5fcb909c558089" \
                          "1e1a8261578b974d9f901acaca09b701c33ee8dbb5ada0392bc5e044767898f4" \
                          "3227a3f5161e11d061ea80df67cca683f159f343efcab688ccb471ef8fe2501f" \
                          "4be39e18a002a164bd8560b2a03c6c983d6ef5543a5da8222eb0b712e7b1051e" \
                          "683ebad38becd96c8207dc2ff1e41bbf223e2194fb051e9fa18ee3273999e620" \
                          "6a694cffaf54e3f509108985f401747ab613a53225ee7cff7db362cf815a9bed" \
                          "c04aad1d3ed71006550a7900ef6140d31d85ae220ad493bcc4407bca7b4db2fd" \
                          "8c89b33e5b080eade590a2506549f7e6ada2361fa267fdacb3035a4456bbcc72" \
                          "c89396db3ec45cf609da798358a00a9c98ac06a7ae3e05eb526b3798be3481e0" \
                          "a5212e7394e035c42dc5ce9742a51b9be10ae24e1c57adb82d00e83759da49cb" \
                          "9518a56205fc8989cc20dceff40d49825b217d12eb8314fb4492aa41ae001733" \
                          "9364df43d0b0670636d75265fec3c03cae20daac456389075f14e1ebc50bf4cd" \
                          "b634f3f2e515b0392f6bc6d2e61b5897497e2792990a621f9436d0d0daf35a7e" \
                          "098c8b497979e0487156e96df7135daa924d9db8912607b6679ca94de155c454" \
                          "075d61498411c793870f864c710e6821e2169d0a50e639f0cc4679887fbb71db" \
                          "7692d679b2326313695cb16a1b702b77af3b9e6a3ef66eaec311595bdc253724" \
                          "9fadac16b557e33f5dfc2f85340728e3066f778fa0c171a4fdccb11caef9f323" \
                          "06884a4297967ab1c3581f1e09d9e357b6d4932a2f34f101c18a5fe76e25e76b" \
                          "7f7045417598098a69aeb03d67f85d475f9694b750415b70913228a8e4958af4" \
                          "86a4e28a24d0c086a224b1b0efd06e24aeec419b700e0eb498c41b63a31e49a8" \
                          "a36cd784fb123a0f7aa6b286dc316105853ddc135d02e91f6087e98805774eb4" \
                          "63898908034c65b0ceb2454324840c6ec607ae41945850f74bebdf5245ddaae0" \
                          "03c480339c7249b88b74a44091fcd5223c26635773a77bf83ba5a08fdab4af69" \
                          "e21d7050955bdaebfa4cbb8bac36e27be4f68f1274fbebdc5b4a9f943d3f7516" \
                          "c7a4a173bd3e2ef740aecb51b3847074d1587c82bff5091700520c71ef553703" \
                          "9f105ddc02a5287e14dff7ad53c21e16b62a15b2955584682c2aacf784908653" \
                          "f731168d90b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                          "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                          "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                          "9548769d"

test_signature_Token = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                       "c5409ec29c0aa9aa618b4c8297df4d3f96c453524589853260667b99d17c7354" \
                       "ad9f5409d802ab07d724d00e641cd943789d40305601ed925bef94055b31810e" \
                       "f40a8654762533496a7b8718b7596e472e31670f083b435300569c56366538b3" \
                       "93d6799e182decc00ffdcb18fa866fb08bdf6f44c03ad0117b37d76fb3190847" \
                       "b68df84fc346698047b8ab99d564093b0bbc916e093c995100ab6254b02fcbff" \
                       "d06fcdc132b57a7bf5a0e5bdc3c8ae053df6b1950e22b82d575651cc85618dab" \
                       "5254768f6a83ebcaf1418846ab3fadb71c39a24d18bbf7b64afa71f0a8f109fb" \
                       "edf702fe41c899701a7b4ac5d1687e6ab5e44999afbba6e07dadea3010ef3d9e" \
                       "bbfeac245d8f7f63712283280ca68d2f32ae6bc4241e927eb6a25094d561351c" \
                       "c869bab240435c7d9a51be980aa3eb1c65c52bfe640aeda4f64454519fcc28a9" \
                       "afcb988a6933df7dc72c63144e28f621c7bde1876246a4a978e080bf03de7971" \
                       "10fa26ded6d8579156c92b654d712cba48bc70e1691cf257174137bb3172f30e" \
                       "5b9d4abd391ce8ef781a9396cae8f7814a25d74e09e7d95757eef92b9acac5d3" \
                       "c2b130aa0eea111ead25f32e885f5f0c58cd6015f96573dd48f820e152fc5b64" \
                       "71cc9b5f3f2393a4866022f5da69c0bc12707bf4eead0dbc13d09c3d9bcb39c1" \
                       "aa92b3a7f71deb19e22d5d355a9fe15c731655d900ed3cb0060fbfc2569b79cf" \
                       "f658c90f08124c305fb5ef005775f93f29428a4dc5d1b50c2406c6b5f9e5b74d" \
                       "bd4b8b7e403299c895f50cc4d474da7f6987a371cc34ff30db9f03794f5d2488" \
                       "316c2aeae6cefa11dcfcb0d4378342dc20e818354def709e08ddde8dda55c15c" \
                       "04a8bbdb6fb31772c7745bfb8c46649189d9bb5e065ae21b468f21f3eae64077" \
                       "776ad299911dbeaccda28e5bb8ef8496fe0d7fcfb0f33718c99edd5b922397ae" \
                       "deae61e4d3f301e52124357785ad64cf0ed20d190fdc022a42ce090d0bbcd779" \
                       "5429e268dbf2d1552f60ad0b7edd254cf454cd207fc34b130b7ea896bd8322d9" \
                       "130b4e004a4ef7b9d5777713f42aff893335e75c2bbd2c2b2a6cc3ae16e31a74" \
                       "47f03301de792482d40f01c662ea90bc4d073c3959103cd05f93ff6f33babc09" \
                       "0185eb19be2e7293ec928f012d9fb7868e3c456083aab990165d3cd573d1f2bd" \
                       "119b543b9318591be83339c5afc106c81c2e11360708a618db848908f5817b8f" \
                       "825039548987c38e637fd4dfd3e2b72e3d976a69832fa8410febde2368d71761" \
                       "de7a2dd179481045da53b5eb5ea53ce195a91be6a6f887ef0bc6a0b5e64c635d" \
                       "79bb982bad343a49c3f30d321f03b43929581fc4e63316b7feb210e8f305c7b5" \
                       "de390f80366eb7c300817d131e1e5d77242d3c917eafe1d0e5b12c05859b5ae3" \
                       "bdefdaf26a06aa38830176fb4c409fc183445cf662bf4e7e2042023f98487e15" \
                       "414b10a7e59026a31d61f293b85c1bcdd96cf08c4368e741203f53a71cc6c34a" \
                       "00b660147e90ff9b1f5a2391c4e5682e038152e9267dfa4f763012222604be5a" \
                       "de22ec7eba1351ed26b9fe8947a694647c61f4af4ce02d2c396eae87e6593c20" \
                       "9bfd608a01889ee0b9021949acd69213df86ee19ea091e3bf9d57caafd2c6a04" \
                       "e588d4ee16308e1f3e2dbfff61e42e534b317b0054018a457cf4e9945f66975f" \
                       "bfb4ae5c0c1d2b794bd9abfeb31290713aab9a14ebddb457e05683efb40ef618" \
                       "9faea2edf5f4425d212e90652234fc8ae3ea90a392eb8be11f6d57fa08d6bad0" \
                       "9777c22d78f60e3d2764d6decce995cf3d65dd6d0ae7d413c39ea7018e88c683" \
                       "561faecd0918de5ff53bf5576b6a172cc027d3e7d9e761c511eabd41b9dda95e" \
                       "d907b16cdae79bd7f6f4d8dfb567ffc0a6c779566959c9dbe9a717e2e6a1fa9b" \
                       "588dc8db0d349ac447d10b74e97bc8d56c84b4173d00fc7762afdc77ce5ac4af" \
                       "7e06fc12e864176357290a75a1fe4fe560d990dc7ea84da038efd443b2aa1ca7" \
                       "5ebed666d9014b6c15173afe7a9bee985f8083892a9e5189c7ab4931dfc91927" \
                       "0e04541422326afe820c21b3621a9dd74705daaa1b20525864a215cd0d6159f8" \
                       "16cb5fd201ee46406c1002a7fbd2e2490cba26b4e03ad39ae9ff7c9951da4d33" \
                       "3d2c4d7efb5478ec9006fe5c73a70eff0372d139f82cf8ef8aa3e576ea92f8ec" \
                       "49529fafd3fcfd1d7aab96c36deca8c9a8acdd818ac456c90d1ba0d0cc32ef7b" \
                       "1a7cbed73502c0d7aba17673791ccb4e841abaec1c3ce9e788ff21116e379b22" \
                       "5d0524256e073c64e4ac3721e88fd80348204ca1e9170f3c7a4b4ce985fddd9e" \
                       "2e8d92c7f3e7d89f80b0da70bcfa880dbf375839d90f1f8763cb50a669a7dc09" \
                       "a220b553f9b8891e909f93a75da72541ccddf1424d49db9fb2995380c42c23cc" \
                       "858e241943270d91fed7c615e024338c83c134125c64e921f1d0c3df7698a257" \
                       "0e3024f804fc9c78cad7f97cd99bfd37a739a91714cbd03e9df018790feeffc5" \
                       "69b654eaa71434bb6b110ac97104200a7eabcbe60ff61d248d7f630e2d9fcb67" \
                       "6b0727d0c61a62a530c1e429eb1a968cf7f1d315873cab1b10821e044dc1e23c" \
                       "eabb5cef25bbf7ad05aeef1cc2ba8d2f5718664d63d2dcf7137c468ac3e73448" \
                       "beab51a0e3ccc12a3ac82bb56848ffde5c8fcc67a5eda0a72f5d2b054789ff91" \
                       "7339bca2628d9a37b507a9697865636eb31aa84ac6307aaaae18c79cbeac71fb" \
                       "0b3c950940da8e0395c321f47d649d9a346a74b14905678a9931bbcda074585a" \
                       "d22cb9f53763ed3dca01ee04c9d95bb42f4e5d9ca8b9f815d0eeef63ee9fdc56" \
                       "b7dde5a524e0b028c31de0aeb05c8de26648ea11d03ac2c8a47e677d95f4f090" \
                       "eb24c40bc2eee1646c71f87a24d848d0a0be51c8ca6044ff7d4bad2aa6986f0d" \
                       "28a43235661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                       "b3159b6107ea796cac4c62073234462b51a0659bcd44e933cc073623a3d2352d" \
                       "25bc698e451c323b1ef22959799d75fe357910332a16752cfb13e6745b728ea8" \
                       "265e31a464977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                       "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                       "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                       "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                       "9548769d"

test_signature_TransferToken = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                               "c5409ec2baf0ef36835e9d1f19cfd9268be02af016b2602fc137795b22c68579" \
                               "19918990fb9d66a70b62b9537affd7d7726e241ddc82d67e113c58999e53894c" \
                               "28fa65a88d3961ca3a9dde367280c13e21bc2750b586186cca88c39ccda7cf14" \
                               "21936ce98593ac64bed1fe194687ee6cf8e576d14c9167042fb7ddbb6475a6d5" \
                               "46ad2979754994c15a37e1e7100770d34768ba43481134c4bebfa2eea2f1533e" \
                               "c8839e17ee602b676e4a5b02ac1fd97432079134e1c19433b6aa002587f60c8c" \
                               "fd91aa7409fd9b88b0f8120ab35df891d71ad80e1a4696ead1ea09aa272ccf17" \
                               "43dea2302444464861fa0409884ff880c329d35c06e5a8762963058ec1dd6a49" \
                               "27805adc976a0d84bd08faad0ccedaf839a650a580eb63ab00c1ebf8c4728098" \
                               "ba1a7fa0d99bc88e2412cd66b1a31370bf208c5dcbc1326bc14abaf81e266c7c" \
                               "136d00ab12cb8344348527256356f609c3edb749aec0b2d10404155e6a5d4958" \
                               "79ee7958d6d8579156c92b654d712cba48bc70e1691cf257174137bb3172f30e" \
                               "5b9d4abd391ce8ef781a9396cae8f7814a25d74e09e7d95757eef92b9acac5d3" \
                               "c2b130aa0eea111ead25f32e885f5f0c58cd6015f96573dd48f820e152fc5b64" \
                               "71cc9b5f98c9be9e8599f184da1c9f4024fe0be5666cf0927b8d4c8d788491f0" \
                               "811ad2d6f9c5cc442f6d42affe88af0534c062df196dcab6ce6aad685a3020bd" \
                               "228cdb57f68b96484e329a83b9eb09909a02db59000c4a1628a94190b3d2046a" \
                               "9fc72c0dbbd479fba35028b6dc06029b32548c153d205f27c552228cac090e56" \
                               "3746a370c1a6989c5eda632de2e49f9d372817f592be2c7a0fe3ae7305883ee9" \
                               "4257358e32da1149b0c1190f40788ec84078e92ff18af9b2525a04d1eaf90a57" \
                               "1eaa0662911dbeaccda28e5bb8ef8496fe0d7fcfb0f33718c99edd5b922397ae" \
                               "deae61e445d2a3edde93674007f05cbf1b0bb101f32cce36e863a4f3e523d0d1" \
                               "edf9427da707042055170043f84f389397e605d0c6f413a89691f67b7559954b" \
                               "eb4aaf7437b2ddac4eff668122e9994643a46628671f5751c807c63b408c4245" \
                               "4d5c3789682c1065dcb0651f8a270999e07b220afdda6d16afd0f0f90d4d0bfb" \
                               "8b1b48690410fe68e884a43e4386870dfef3194022ba3b416026aaf39609f7ce" \
                               "43bd8df4e7a39a678cda78f23439ccbf22a1fee11f3a066827f09c0aa27b814a" \
                               "50d6e77dba711dcbd5236bac6c202c273766f1d415279ed61d6963a8de198a46" \
                               "a06ee6a268e44c87d0dd8fd4b8d7e5700f9f2c641b7310fc9f8bac7d1a4a53e2" \
                               "33bc9f8806a8c3df846ff94f4555ad1c25dc4fd0e4f4a8e9a68e06521f23e5f8" \
                               "577ec2322eb54e05c1ffbd8196f5996c7c43d0b39e1229c4836a2e357746b3bd" \
                               "3618c594b56afdeabc8ac5f18c0dddab2ced6e46d5e62d0f71fa52d34f68ab18" \
                               "3b20db080596e28636c8ce8123dc02ab6aba67604ebdf7e9b2296d1ae92e51c0" \
                               "dc6ae37001efba9fd0e33fb3b832411b8a249b53731ba1570a2511b737169551" \
                               "1d10e3efcb1c7249518bdd624fc90dbda70100d6e38f065c6609a0183405b810" \
                               "0b1966d5a96f837f8ea955a3b28299e5a92d1bef2d0a9852ecbe92501c1acd6c" \
                               "380218ec16308e1f3e2dbfff61e42e534b317b0054018a457cf4e9945f66975f" \
                               "bfb4ae5c46f537b4a375de7765143c4af19d93c55b918b03616ddb41c98669f8" \
                               "d23de08100d05a9a4fefbc3ebe0ea046fbde88303af0ea0c516f7c8efa7f045b" \
                               "3ed303df23d251dc3d3e4b2223c616bd78e1af81fd26e77fb4de8543b88f9db4" \
                               "90529b660918de5ff53bf5576b6a172cc027d3e7d9e761c511eabd41b9dda95e" \
                               "d907b16cdfeffe09a5f588c215005bf3376e30620d0c54cc535f1fa76c2264d1" \
                               "150114a6f62eb1109d942b98db059309eceb8730a3aac7479eccb8c784adbc21" \
                               "44c874ee51b1fe29037658c82a793c8c27cbb128cf68d868cb8fd7ea2d0f833d" \
                               "2b86e4e5d9014b6c15173afe7a9bee985f8083892a9e5189c7ab4931dfc91927" \
                               "0e045414fc12c535f2f1ae0c025f31b9536522df9d9ea43e642f62cd4326fb45" \
                               "1880ef3788a8ecf6c2571e4793954e7a6a17b71f2af5531706a6a2223c162af4" \
                               "b9d9fc0a1b76296f1e549177259ad65a169b86971869ca457a64ea7f9e866d1b" \
                               "87dc92a3da843186e603b73c4dbdb16393557a2dd8db557a568f373b518f7c3d" \
                               "072cccc3fb11c05465424c37d075de97ac04dbf141f1f7101113e603de6c7273" \
                               "787265aff98f2afc1ae3d679b548a4aa5473ca9b96e8d9663d008fbe958a605e" \
                               "82b1aa71fb434cb583f53c9131b2531ef669dddf5602f08803e5b3458dd9f540" \
                               "7e58ca30276741cafe7e33065c60e9d3f522bc891aff2f1758fddbc7febe30dd" \
                               "f92d70cf161a962734376f991c9a46cf273ab3be9022ca382b9b28c01e2aa119" \
                               "27508046bcf6e939354ef1d4516761e8876f9322103e92cb80c3be20c1df3953" \
                               "4b786b0547b15276e807b04d8ef3ca3765af0d3bd48e39e1096906a451303d61" \
                               "30d86e4ca97cc7ded05114d5b904a67ad88ae9c5d580ca576a9dc24a2afef23e" \
                               "2ad8aff45876aeda7b89938b0e0d80d037ff4b307d689ce3b6e98b3474e60622" \
                               "c3ed17e85bba7fd22f6cc2f0a62dcd29a113fa27fc2ffb3210d57b36bba22e13" \
                               "173d1b71e44b788eb6831e7763500bf36f27da1de945685a0347c05532e52b80" \
                               "bdc3411eb8a72f483b6bb56b66a28e8fd1ecb81a2eae493d19ee2e423d2ee2a6" \
                               "e72369aada121177e9c0429217bb275b0badebf9af581376c1e2880d8ab5e9aa" \
                               "82c4b44c551b50278a166641f22deb6528b0e5c39b02b833d82acb1e53919465" \
                               "19225fe570aaee98e8bcbb0ea8105d5af302f6e05318fd7a1f607a152f2f03f7" \
                               "85850ce5661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                               "b3159b61feabb00594c2f0b0c2cc474e2c70a317c1455e1f2cfecac973f8799b" \
                               "eca6bb29451c323b1ef22959799d75fe357910332a16752cfb13e6745b728ea8" \
                               "265e31a464977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
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
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207a874fedc',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab'
                         '77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual('6e955775c40eeec1f45064961d2a48335e56687f12d8d5b1740c6f16559086a3', bin2hstr(tx.txhash))
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
        self.assertEqual('010289c74cf0d07cce8f265be6ffa8e5253e0aace2625bbee01611646a9bf1dadabb8fbc9f62',
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
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207a874fedc',
                         bin2hstr(tx.txto))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab'
                         '77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)

        self.assertEqual(test_signature_CoinBase, bin2hstr(tx.signature))

        self.assertEqual('9b11ec3edce4c0ee99d438cdef2075bd49a14a8fa917243bbd801f064e0dc97f', bin2hstr(tx.txhash))

        # Test that specific content was copied over.
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207a874fedc',
                         bin2hstr(tx.txto))
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
        self.assertEqual(tx.subtype, qrl_pb2.Transaction.TOKEN)

        # Test that common Transaction components were copied over.
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207a874fedc',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4'
                         'ab77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'QRL', tx.symbol)
        self.assertEqual(b'Quantum Resistant Ledger', tx.name)
        self.assertEqual('010317463dcd581b679b4754f46c6425125489a2826894e3c42a590efb6806450ce6bf52716c',
                         bin2hstr(tx.owner))
        self.assertEqual('4c16212d469ab9e65f5470f3fea77535658cb4d49bf78fcb94184faf173eda9d', bin2hstr(tx.txhash))
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
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207a874fedc',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab'
                         '77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.amount)
        self.assertEqual('d176cb3d9071f7a6024601f334c1b9e414494c414a11cee6b88622144222e5e2', bin2hstr(tx.txhash))
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
