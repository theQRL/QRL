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
  "addrFrom": "AQL3xLfc/IPo5Boazr5GoFgil0K4gAsjotI/Pawm71JyB6h0/tw=",
  "fee": "1",
  "publicKey": "AQI8Uj+cwm+ACGPAA1JDkoBv9t83OstNR8xge2I2X+Srd88wGNMh333LZTyfeWhnPkPRLMJuNGG19CX9XZd0AP6l",
  "transfer": {
    "addrTo": "AQKJx0zw0HzOjyZb5v+o5SU+CqziYlu+4BYRZGqb8drau4+8n2I=",
    "amount": "100"
  }
}"""

test_json_CoinBase = """{
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
                        "c5409ec20c544b7348356242fbe09e2e16a3ae7b4583559486834b9f3503974a" \
                        "a4f7997658feca7f9436abb93715a5abb8f0a4d6b981dd9f4c033d99fc179b8b" \
                        "ddb1ed42dd538aad6c183a6c232aa9e899b669cc3422fdff1dcf56de6696aef2" \
                        "9443016f0d55bb9e6f1be07539cfa625114e032c629da9dbc330aba792a4599f" \
                        "c760e5dc9b57232578c63b05905e6de2bbb8c18b602ba80dc0f942f11e7e520d" \
                        "45753d9732b57a7bf5a0e5bdc3c8ae053df6b1950e22b82d575651cc85618dab" \
                        "5254768f6a83ebcaf1418846ab3fadb71c39a24d18bbf7b64afa71f0a8f109fb" \
                        "edf702fe41c899701a7b4ac5d1687e6ab5e44999afbba6e07dadea3010ef3d9e" \
                        "bbfeac24b1a2bf05a24c0e47c425d3acd060eae3156cae0c8fe2fa63e93b08e9" \
                        "a6fca0611f141cd21a0c70da293eb6434c9e591d950d7fc170dfe46d0ecde365" \
                        "815dbe98a0b48abe3d03da946dbe7672004a2fe006eb60107bdb2cd3db3f0956" \
                        "87a5e4d4d6cb3b9550a254e79c7abc22fbc62f297b035385fa986fa28e580f1d" \
                        "ae4bc595e038bfbb1707bf3b6a73cad7f1362bc7991c8fb8e933f2e5163f5944" \
                        "7fce58f45c761996a5a2c1a03af11ea4e111e39b1919b0af26c500be1afec879" \
                        "57696e7eb59bb279c606f6c502f797e939ca7953cf1ceaf61043b13632ed6042" \
                        "6c62dcd33fc81288abcb7f81814516f760937b114610c49f4b359573819429f4" \
                        "fd30c9402df8f41099f6d7b1280e0a6d0895a24cff32b965d57bfa7a7c704110" \
                        "ee27f4408202028f7ac47e8aa48f945f0df4e889dca508cce708be5603220f4e" \
                        "e9029860e8f3d9196ac6943623456a5b8cdebb7c94eb3dc13302ac921a20194e" \
                        "f6cccaf5481e24dc9c76fb68de25ab3f68c92285e79b85ad591636c0933e92a7" \
                        "e5458c5bd2c7db4c76e2211476b293270f9985b84b8dbc4aefe48d52ab98c0df" \
                        "0bc93fb5c3787cce9bc543b01d970fd91961e82d50234aeaf00aa810f442e081" \
                        "5d261431c83ed774a5e90c93aae6949a2bb66b3e8b335aef04012044c94a4624" \
                        "a628054efeae5e16cbc7c37154f828a4aa090a219dabe3c0c07c437aeb46a423" \
                        "3454d8b36051cd153c2f51af21a57b013240feb6943345ccc55fe7acf72b280e" \
                        "1ecb435930579a34b5eb6a60fbfd39cd466949f5b7ce95d5a9a0c523c67af66f" \
                        "050c29d1d1cff192412d5b8b14e32e1fedf304b7f66244fcd946f25740d57f41" \
                        "1a877eef40fdcee05b86aa54bfb21acd7113de786bf0a7f148db63c3bf01e74a" \
                        "b1430ca315976a9f8ed4195436ecac059a6bd1192fa155c504d8e181a1df7162" \
                        "a150ed43847c14b5b43b694b678c67376de3969909edbf1bc09a6ec06f4e8fee" \
                        "fc89e25afe1f5adfc1253bde505148e684eab6e14252c9429a9d05a771fae609" \
                        "77c3efd1782b3e7e197d215c103a448c8713e15172e1a7cbfc54b5349a041b3f" \
                        "ecb099b09faa922ba72f25d92f00f1beaa1dddc2a7bbaff8bc1cf70b78b8ee20" \
                        "1b5c701e7e90ff9b1f5a2391c4e5682e038152e9267dfa4f763012222604be5a" \
                        "de22ec7e730ad2f98bbf7209012ba4c53cde7d9db868ef0608b3b596f28ed9cc" \
                        "c14efb48325edcb81807c33f10aa20bc221b124f4526438349ae920c55ea7e11" \
                        "c74fd4b70d94c5a4e98152efbd952604062a02e33fb630a0a4c97e43e05411b6" \
                        "1a768e18582a526958548efb71f302e7ca31b425b417f681a90e6c91993ac0ea" \
                        "3964b49f8ea3b99c0f4acff7cb51ba0267cb3fd5eb6c2e140f41d68316fc9f76" \
                        "6119027ab17cce5fb9480c41c58b2ab29ff5d0a1bc49bdf3072d7db375a88198" \
                        "b241ca459c608c75aadee7d9ee36ca36cd9a174c4ca90f4ba7b3b9acc6f9f85e" \
                        "a0b8c320dfeffe09a5f588c215005bf3376e30620d0c54cc535f1fa76c2264d1" \
                        "150114a60ca00723c8a9b3f35a8f4832db8c1c3892085f539392099cd624a225" \
                        "90bcd7079a94de8dca186a82ce68d5b18f032b5ad33e7303c31109418e77d933" \
                        "6c0fcd13c3c1dbdb0031231f3a4739a1589cd6052b896115b4087acf06d35e2b" \
                        "649b5f5e2aada75a35575509fcdd0d61c02f27d0fb000f7e8f0a6a9e6d7540b3" \
                        "e3619f1892ae090e9b32fb3f14c33dd360b4807ab6a7a51a0718d9a3ce0c7f39" \
                        "c518003e1b76296f1e549177259ad65a169b86971869ca457a64ea7f9e866d1b" \
                        "87dc92a3d74e51f15f88185a4f5378d2b5f43bfe18dd7e6b9a625265f0fb73d7" \
                        "9efdca4ee04bd61f719958e6b8fa301a303a15cdd0ab3964710c85c8a9a79c90" \
                        "d1a14083468c277c1266cc58bbee1d83db753cf04340e141bbf67160e0ff8bbd" \
                        "f64d315161facfae2f7d1eb9e168ac573aaa7588f1b1b1b9e8796d6dafde8877" \
                        "6e93aa34276741cafe7e33065c60e9d3f522bc891aff2f1758fddbc7febe30dd" \
                        "f92d70cf1404c3ad526d8b6c79af896e5d365761f223ed22bce5b4ac91854c66" \
                        "2cdfbb0fa1ee5fb8712f68bdb750423979421aa8a65d7fbb696e62ca0fa3e946" \
                        "ba861a73ddb6ee71f403fe392752eb2e60e80d224442ffae3a68625615693dad" \
                        "a1481fc08f7e38840422b8e30f16a2e11e4966d7d7af851f264018290f4c5303" \
                        "7630e5805876aeda7b89938b0e0d80d037ff4b307d689ce3b6e98b3474e60622" \
                        "c3ed17e8357b6aad8bd0906b9807de17004cf2596c03be9600f30742c388540f" \
                        "e55e88c3e44b788eb6831e7763500bf36f27da1de945685a0347c05532e52b80" \
                        "bdc3411ea23f86a5595466826fc324441864a82ef315a0ed90f448a629e545fe" \
                        "5abb70b41cb8f07aba6d049d86cd3a7f135a43869ddeabecc59e4c8a97699d5b" \
                        "6e1734861e092f753b3ceecd9ea0d7d69897e72e171be00cc34dff2eb7840c2c" \
                        "7e9613ade22c2f985ad798940d8fe814f5319833c8e1f2b04bced68b86228185" \
                        "360ca867661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                        "b3159b6107ea796cac4c62073234462b51a0659bcd44e933cc073623a3d2352d" \
                        "25bc698e451c323b1ef22959799d75fe357910332a16752cfb13e6745b728ea8" \
                        "265e31a464977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                        "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                        "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                        "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                        "9548769d"

test_signature_CoinBase = "0000000b01c683d859b4f21c43e0564be6b9580356fd983f5ab2e25ec51573c2" \
                          "fb2bd593bf23fc93f3a11569f5d18eaad5c7346a789fd1f4c3bda3ac2d3ae787" \
                          "d369b18a369d9b30250aa6dedf4d17e8aed104a449ec1e7b0f32cfb299645c84" \
                          "5e535292f23658493d5a169b6486ca9aa85d0f168d5ab388b3d16a3654e1b814" \
                          "942de27497b4c518768d40e110b23ebd9851adc9c060c476bac93b93a342cead" \
                          "4979fbc56497f4ba44ef2751707037dd18b3e66997a346e88d1e7426f06015a6" \
                          "5305759aca4a309302e7a25c4ce9c168cfa3331dbd9babb2d66373492259c95f" \
                          "7f5a7e43d489e180ec05b501c1b278fcaea9dcc2be1300baecb3753f9bbcb933" \
                          "0992c2c8a28c10592b4f1d38845c7638cc79508e86012cdabac66b0f380cab56" \
                          "5527e824ac49f81c777a65aa476943f092644418d77160e92effb61990e3b670" \
                          "7ee6c58959576540c9adca25074cc9a0a81c9b2fe94e40d1ad45b9b92f1601b7" \
                          "c87e8f59c3a55dc60fc50d931e3723343a57879ad9f82aa59b31ed00da30136d" \
                          "adbe361fe1b4c53296bb3acb612359fcb229dc233b56d58abb6fb94bed3d6e77" \
                          "f1b50036e0ba63d7127c7ae4b275e2f9cf2080426c5e6675d962f5ad41342544" \
                          "fe183f408793f82d8db84cd524bc409faf62f4d06613976ac33178960a100f9c" \
                          "6105895ee4cba33a4a4187c3dbc6253d583afc32984d212f917a9716934361d0" \
                          "1700faeb537aee15f4ca15cc9a3481b7d13ae94ec5b9613e7ce2574f983d00bd" \
                          "a54db8f9bf170eb10ddefff6a85357f093e34217cced68a4999487deea855cb2" \
                          "3db02828d8cccff73a55a5dd888e54057a5a921d75e977326954e98a919e7554" \
                          "1ffd862e71f145365b8ccba8af86e4d5aaeafd3d4fca1139a1fed744f0d69637" \
                          "1f7de6d23b5dd40b78f27172853e5a6e5a31733dad3aa0fd60adcecbcb3666cf" \
                          "9d01bff6ec856ce6cbc83f754179ca358e4c565dea6e09967474f3885d752c5b" \
                          "1e75587bf3eccc597f695e425016a887fb99f3aaeed8593d3ac7e21c862e51d8" \
                          "a27d79a0e0cd385c96606b395e5fb31811131f16774368ca53161cd22fe82494" \
                          "26821a5c1df5932dee992c54d1a923f6872342dc5e0be9ee84375b2fe3d74c74" \
                          "009e4fb18fc1ab2fe5de772f87b84bdbc88ffee976266ab236ffe81204d63194" \
                          "c2e898ae5822a19be0826ae2830ae4aded0fae2312d2a0da2242beff857679b4" \
                          "72c88d46bebc66dfbb80b0251f7d697abe394c46838b32629ed231633bb25160" \
                          "e63628b6a3bb40c5b360e1a31459d413018051ee739b855126c76d9cd4c57a52" \
                          "f4a7dbeb82c64a14434c218679d96f75b296eb07e6acdc02ac7ad213ff132a82" \
                          "02ad64f71b4cad97fe49765b6e7e5d552051bc1bf27c7334f5fa3200ab276d18" \
                          "3d890eddd4c6550d1295bdda3fbef97bd1cd050170a658fed19a7315ab49ed6c" \
                          "1cd2d4e800566e82ca1f46b65531d3f56da13f6e9c58aa5080cc9b7d7519187d" \
                          "5a0eb157f392f0df8245e5dd60360473692136057f92577d9ac807e211472f80" \
                          "6be4131089fe39013e550d1aa72f702926b1871c277e30c1f283f9a2e0af2b4d" \
                          "3390974601bf48a46b8b9a6f282147c608f91822f4eb0a2bb15e7c0bf08c1fd3" \
                          "a2607815c87719b4df8694bdb3766eda4a7ebb25881439f08b540ee32e9329f5" \
                          "951514116581344d8279ea55df5cfe1d407fd3ac509aa3d2bbc0dfed90c8412b" \
                          "838914a5a9591f6ee872126af70be57c405e8b60a2762f39b92a08bd2cba84d5" \
                          "8cec40e3ab831efd236e676cace5142baabdad238928e86e63460e56fe0b4b1e" \
                          "f40a8b9777ef85b511f916ae5c41a28fdc72d653418a19bd69d1fe1897763694" \
                          "61f55339527be73ed56422b843bee5365f518b1dcdd1eee24631aff4b022793f" \
                          "11f572e653897f017d82874eb33227f79f78d4c4bbf5c9a1912642752caacd47" \
                          "8ce8636421deb73d4f88ee9c745ba0c571d203c2f989894c15f908be6a976f20" \
                          "1cec811bdbc41c88c60debe536a49b67a491f084fe6bca9ac82a1679dcb361f0" \
                          "1180c86ada3cc12c940047c50e6ebe9df6ce7c8e795c156b273ab6304dc76bda" \
                          "1712b82e72d10c64f6a58d6055c456a5518236c3d55bb84682d0e9ae15bf3967" \
                          "f032d0febe70f9ec67f736d5a21320a16c536e58ac8e446e37481548ddb29b4d" \
                          "74d9a25eb3a9e6c41660188be9e1e5575063ef5b5c7a491cd4331d3042375fa4" \
                          "d1f614576e0432517d30c830bae9dd7cd3be4d72855486bad8232a5601b423e7" \
                          "e906936618d0ab85f8c25b026be31e56bf11761dcca2bff6f32a2a45eb8c8bd3" \
                          "d031270930fac44a70eb01f79615911bb314defb45ead3c0b0062556c1d5bc77" \
                          "8080ccd755278f3914892b4f82faf0dafea30536b29eb0c95a7cb90b69064b88" \
                          "25688d08aa1ce37dcde61a59c6e738d00c6c5b7ed36b52cb67886e21da4856c5" \
                          "cc53cdf06d675506fdcfe6b9f7761fe2a869bf64ca498ca5c040f7292baa0ce3" \
                          "99290c452d7f79ce13227bbab0a801218e04d6d830a2d2da1f51046ac9645987" \
                          "a815c03a8925edb4ee0f8bdf3d988bd0d5eaa14be31ab304dce8bd591c830e09" \
                          "3f0bcb1e7d4c1b8d6325ca6075d70f5a9e37f9398c0954f19d61679ec0d8836d" \
                          "4f5f85e5337fa6d293a0688e423aba95fd47922c5522af7ead506c8dee0636a1" \
                          "62886550c2c0890b9cb8ab289ba778dcf26fdbaefeacd4cf3ddb05f35ccc60b4" \
                          "5f774c54dea75629778bc93a8716847b2566a68d23ded8f21cd91329efa931d6" \
                          "a7b7b0bae043889f7198efbc96e7ce32d9d15606b32c1177ccb7aa5c9e32fe8f" \
                          "e65d20d3328d05e830d2888610579533a0bd6dbd21e43fac2b77c96c91998d89" \
                          "ae146a45edbb76b2ab79a5dc4b4305ca662f3d80d3b67fc1a343d46640df41fe" \
                          "f502fe535061308fc9bc638dab70d142e4d27faa4836f63638412d72b8ee0567" \
                          "42d68eb29c7249b88b74a44091fcd5223c26635773a77bf83ba5a08fdab4af69" \
                          "e21d705025ff166fa452642a1e4babbf8b188422ce75389b6335091204f0f03d" \
                          "78a5010e2a196f1438b826571c733abdc93b016cb0f27b9444a47a7eceb0483a" \
                          "1aec94c102a5287e14dff7ad53c21e16b62a15b2955584682c2aacf784908653" \
                          "f731168d90b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                          "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                          "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                          "9548769d"

test_signature_Token = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                       "c5409ec25ea69350d1efbfd7f7b0eb5e409090afdeca401fe438008ae1ec2226" \
                       "a65c559c5f0520c8d71a7064ba435d442babc8ca56fa9c911d7b1a141e28f123" \
                       "e51dd014366869103ee0b5821deae396675c190ba006b71b2b0eb58eaa109b70" \
                       "3601366945f5947ec4f157b1ba6633d1661f34fac856e632fc5a762836cda764" \
                       "0946c385b459fc21d1223b1689f561e455cc87206084f5b146d45b440307018b" \
                       "15f987264d7841bd8d3ed570ec07f30d72c9d00288e2e0a84a21625d45b2ce6a" \
                       "10acda4a3ac8b7a35e15b88fc4c7c6ebcb00f6c7f0b5c0ef8252fcb26d1d6b58" \
                       "c68368c2e74b51d17dd6821490f150ddc41abe09cd5146b9480ecb47cab94656" \
                       "3d3f296af176194360927c6cd749455d2f8b553cb6a2bc8210dffebb7336939b" \
                       "c3061244962151fe79487f03715fe0034223d15fe66180403bbea421673a472b" \
                       "6286dd762cd88ba68df4579caf85a3a874202c8ab29030c81e1c57cb959b7229" \
                       "038c83d4ae3cdf0abf23e8aa448e15e5ae89254923a6cd9db76f156f74436440" \
                       "fce2240d27d9c81b5f57f36c7778b248143242a46d0ec00c7efc12b9e958f175" \
                       "e3642e630eea111ead25f32e885f5f0c58cd6015f96573dd48f820e152fc5b64" \
                       "71cc9b5fd0e071326277365c564f5bc4b521dc24377e89b12d10eb57999168f5" \
                       "dc07d31b1536bf4aa7cdb58e988a22f8986a2ab3c09fcdf7660d2ea658171c18" \
                       "1a8918ac3fc8000cbc3596c27d09a8000af535530a790ac6bbad75cfad7b7c65" \
                       "afc1245e403299c895f50cc4d474da7f6987a371cc34ff30db9f03794f5d2488" \
                       "316c2aea48df4de921c5de24a05452d936acf1ab1e1005927caa85b91b1c009e" \
                       "2fa537ccb5da80106efcaa1c7c8b679b780124fd469b2b69ef8f6f3e91c2a976" \
                       "e08cc9d972a2156104356b8bd525e03216611c2fcc88d2f51570f85990ed6c61" \
                       "569c80d12fa256c571f47c9b5525cfb6cd710270692759a393af7b1cda7ce68f" \
                       "afcf36e776c989a29a2ca8997746424888e7642604f56e681326100fda7d1c90" \
                       "914c5266aced2a08a201f58409c58ac30df89eb11d1e4530d94c0915ebd40de7" \
                       "66d2b7d41122d83044f551c6ce09f5b2bfcfa8b99c7745892c0647799f7d3644" \
                       "1a66af040410fe68e884a43e4386870dfef3194022ba3b416026aaf39609f7ce" \
                       "43bd8df49318591be83339c5afc106c81c2e11360708a618db848908f5817b8f" \
                       "825039540e89420363f8fc7c5a0df65d933441a3624c713fcd978d30e2df9796" \
                       "16b52c7f15976a9f8ed4195436ecac059a6bd1192fa155c504d8e181a1df7162" \
                       "a150ed430dc8ddaf45941d0af4a1b0972e7ee279d76a4291a3131939fe6c0a73" \
                       "a4289cf48eb71115be39802440dbbcba75b840de7c2361e43da8041381bad968" \
                       "42ea8a933a3851bc64a45457178d11dddbf1ee7eb7a5b50da7354bfda415eaf1" \
                       "2fbc22d47dec79f388184eae1ded24278ad40a0543e98cec5ffda8ecf4655a0d" \
                       "3f4f3517852b001a2de53fc3f8b70cecee02cfa20f7571dc3c4956c88423a7a5" \
                       "de97e101730ad2f98bbf7209012ba4c53cde7d9db868ef0608b3b596f28ed9cc" \
                       "c14efb48e5d30cda8e4bc1d71bda857e2cfab6751dd3481ece238c07a5f0fdaa" \
                       "0978317400efc7325e1d9294415baed611958439d34eb9596bee83d652f493f5" \
                       "b4cbe7b322499634d677af73c3fa3d7c8a235ae0a947a7d49cdf977d70a692c3" \
                       "563d416500d05a9a4fefbc3ebe0ea046fbde88303af0ea0c516f7c8efa7f045b" \
                       "3ed303df94d30754698512a2a59f03ce1adb8f93e0afb1b8acad97de55964a87" \
                       "4407d65a28046f76bf4bc8cd42d555c7533847c5d4fe39a46d1e62f0e1c14db3" \
                       "4f7ed5f6af21ec11d901ba75c026cde282a78cf336cc0fe0732fc347b9da5e89" \
                       "e1854c59cf2500f7fdcccbd5e4f60deacf878ffa047f4069688242d65e4b29d1" \
                       "2a6952a4099214612f322c70482aa76c5fabe9e9337de0196281eff09665b88f" \
                       "9019402bd9014b6c15173afe7a9bee985f8083892a9e5189c7ab4931dfc91927" \
                       "0e04541422326afe820c21b3621a9dd74705daaa1b20525864a215cd0d6159f8" \
                       "16cb5fd22ae7d5974d19838095256dc66f2b0699b096a0b733b320b979fa5f9a" \
                       "8d6a796bac92ee6fbed25c5621401507c226fee6016cf03130b3a4e1bfe3ccf2" \
                       "1362a171b2e96e82a10ac423d92d5fcebd5b566b68d0c78a68ae36d18fb6d427" \
                       "c24cad3430ef66d83b1ab27d8f8c37757392fde3e825e9f6c2f8bec3b1704f2c" \
                       "2d67682fed4594b8e0598c8915b2af952168198fb33d538eb5148dd64c2d45b7" \
                       "4e92b7c216b30973ea9e735b8a8162cb94125ba3f0041c92b2226bf4cfa41090" \
                       "e6991eae211ec52e433f4a91958fcb24049c41fcfde1017bfd94df7e123b936c" \
                       "ec86604ea0f0050077a8c451dd060aacb78f45ecfb8903851c85020bbb100d72" \
                       "da12c0177a5f5e9bda0738843eee4d9f52ba9fd05b3e40c45d09a641f605885c" \
                       "42bc72434bbcd37029427ad873e101fdc06e48b7a07f7f436025d5b5419b13d1" \
                       "6da3987ffea61986e3fec3f8c64a8c7af73ef97a3220973989414e05e4c8c1cc" \
                       "9a68ce0ff7e4c628318b6a2877fd7184e6e1fbc96170b249257990764de57246" \
                       "4103c053357b6aad8bd0906b9807de17004cf2596c03be9600f30742c388540f" \
                       "e55e88c3d6c7d6b285dd927a114510f35a3f2d51f29db6928b182cc5f08f885b" \
                       "7b32395340da8e0395c321f47d649d9a346a74b14905678a9931bbcda074585a" \
                       "d22cb9f5fdef858587a55676da83f23dae9804f0528ac745772ccdd6bbcc3511" \
                       "ec387c8e551b50278a166641f22deb6528b0e5c39b02b833d82acb1e53919465" \
                       "19225fe583458c018bce13fc0690a581ae4478dc578499e34f9b47661a74b926" \
                       "d8c20e54661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                       "b3159b6178dcadc32ce5df9ba07f9e479cf3b5c39de9b594dbeaf37493ead6b9" \
                       "80b6633da20ea03c4ca1fa563b24c2d2dff64b61f648a6a827432938f60d6b0d" \
                       "e7c75ccb64977382e05efa9e4977c40d355c2a74f66650ddd76a860318292f87" \
                       "0957567390b6ecef5cd918ad5dc67b0a06072b2d2024161b3eabdba34e5f6820" \
                       "f0752ff53661a658ff47b69f9a2ad11c21eb814ccea8db4e989b580cf4304d47" \
                       "5c770df9105a7eb3d86f728ed6e99295cd5fbf9fca6841afc9d2c44c53800b57" \
                       "9548769d"

test_signature_TransferToken = "0000000a7176fa5565c59a87757ac3a3c45e44847ad298ce2228089a1c9e0b22" \
                               "c5409ec25ea69350d1efbfd7f7b0eb5e409090afdeca401fe438008ae1ec2226" \
                               "a65c559cfb9d66a70b62b9537affd7d7726e241ddc82d67e113c58999e53894c" \
                               "28fa65a8a863b36c6ea80bb003b1db8ef095150c705d9723a4e08457b47d515b" \
                               "dd939b739f8dccda500ca457b5451e7c15eed90220be398700e5f865af361a0d" \
                               "454a74ce5738cbc6797d232b3d925ba91c48aead49ffec97030aab1e965a53a8" \
                               "f80f0930cc2a26ba5de1af5aeabcbac6ab9d16264668658f0958f249c9938e38" \
                               "2cc6600a7df5c0d63652209d3711c7e29d83ddcd9b9ef43f70ba1370bc7fa940" \
                               "51d02ffa77746dbac5afa4e6a1d4c821ecf7c55c7c21aad830ec0a28bf2558b2" \
                               "f123806257c40d4090f750d437e7d721ba18aadcd9a2aceb23c4875a26ed7fdb" \
                               "39b992e92e647bb5a027142e3781b7e6424b4624efe7bd0e13adb00f41b4fbed" \
                               "d85e502cacf18254f9ac2b49b4e6ae9d65b1ca7ec0f0a293b256ba83b9845276" \
                               "1a8dd6b3ae3cdf0abf23e8aa448e15e5ae89254923a6cd9db76f156f74436440" \
                               "fce2240d313768b8c7f67d043642c6ff957c0583e3dd62aab59bee3e5cd1bc04" \
                               "72068891060f10f4ec80643213ed5cfaf3f64b66c585ef0eb5c6d54da3d1dc24" \
                               "1551df80040589910de7c6788107e26068e41327b440f2555f35b0cf7d01612f" \
                               "89470c5ad2c6cd5f2d8625ca92019a2f9eb4b4547ba74b441e664f4383b3c3d3" \
                               "6c7702d720120dc0b3f020a6f9c0c346e44c2a5d65ac9c4cbd1f89c7704d264d" \
                               "5b29b6f3b1998697d1c309e7fbdab3c402b573904b129ee924986eda4a0d009f" \
                               "5d706880b761287b14cedb2ab1e3c59282ff2ef5f1577872ff9e6ab6b903e677" \
                               "60cdb0e307ade4310caf3119242d4beeba1b33adbce61e0480f8ace6d446a372" \
                               "7fa5b656f7a376d87b04c6f72de9efd48b2875db22338665880d032b233582e3" \
                               "b9e2e30c2fa256c571f47c9b5525cfb6cd710270692759a393af7b1cda7ce68f" \
                               "afcf36e7cf99a49a7de7fa78d6bc1a7c02c277abdeb3f388e832dd082b08645a" \
                               "8cc0949137b2ddac4eff668122e9994643a46628671f5751c807c63b408c4245" \
                               "4d5c3789897b2ad87be8ba326a1a17cd6acd08aada370afe6489ec28f8b3de96" \
                               "afe4ec8b7c3b725cd753772172d000222959089d02516aa9a96cd7d0c63183e0" \
                               "e128280369df34ed9bfd70b1e5e8688e568957c8572c28dd5b3c7e108aff3825" \
                               "166929f4b4058485f00e656c84a66e451b75d8eb13f580d5d032514f7f6d24ad" \
                               "739e045f15976a9f8ed4195436ecac059a6bd1192fa155c504d8e181a1df7162" \
                               "a150ed4387251da4bbde4d0f337e47566458efa7fb9f4e39990bc10e2c36dd37" \
                               "abad72a0e14dd890f59d1c38796323485664eb9b68254e2620d9c38655cd3381" \
                               "c89801cff15fb498b2fda89cfc0434174f35013ee2b8f5abe15b4f8e8d3e5c49" \
                               "8ebedb008a75dbdbb1213c15c7614c3bbeb745bb1aa3aee2f3b272ea85394500" \
                               "a03107f1aacf997a72db0a1a68abc6505c258920de091e66bf7df83eb5bfec63" \
                               "143eccc0163ebccb1922b34603433c7e415c08dea587e35d48489b8f8b87763b" \
                               "53c16c244365b517e610263bdc248782c6c008b8f632e5bf21da2fe2930f8712" \
                               "73cab56616308e1f3e2dbfff61e42e534b317b0054018a457cf4e9945f66975f" \
                               "bfb4ae5c46f537b4a375de7765143c4af19d93c55b918b03616ddb41c98669f8" \
                               "d23de081747cc99bb73aedd83670896c91088ca2061183907c1935f4a1fce50d" \
                               "fde21ff323d251dc3d3e4b2223c616bd78e1af81fd26e77fb4de8543b88f9db4" \
                               "90529b664161018b4e01a649a544ad637d09f345776f31b47363eaffa1fbd97b" \
                               "6d79505cdfeffe09a5f588c215005bf3376e30620d0c54cc535f1fa76c2264d1" \
                               "150114a6cf2500f7fdcccbd5e4f60deacf878ffa047f4069688242d65e4b29d1" \
                               "2a6952a4ed41d08662ffbd1a73deb0221e606fddeb2c6b6dfe24f507eed9de8c" \
                               "5338efdd97d5d9c86efefb48490aab0c228e6c05c410e08cc6205e965687d889" \
                               "6b62008345fc7833815adf6fbc2b5cb7f701c8acb30bf9ab0ac7099de6dd3ce4" \
                               "9f3188567dc1e7194515df76aed152b5c082d0a8d58671edbb40f31bcc48c1f7" \
                               "e81c5e9aeb2e6c5bffee64e14fe39d70b7a5d14ef8362e1899a7f58fdc284977" \
                               "86835e8c83ccd739f3da521f5c49f086d1ca0f7fb8d7b8593e3b11d6cb5dcbfa" \
                               "82f3384f96e1c19eb73c85e85d4dd9947daf7f451d6caedf3bdcd1dc30943377" \
                               "bc79ec54da707d79e54ff7bf80cbc4f108e3f6bb3808edc82e523f54c1f8ebc5" \
                               "d89fbc0b91eb8146a8d0fbb32fa341ee57d265224424aaef5c713d453306ced4" \
                               "536db4275807a35e055394d8d83ff02e448816293963ce1734ae28794b3581a0" \
                               "03a542d81404c3ad526d8b6c79af896e5d365761f223ed22bce5b4ac91854c66" \
                               "2cdfbb0f04fc9c78cad7f97cd99bfd37a739a91714cbd03e9df018790feeffc5" \
                               "69b654eaec30fc3a733414ff86ce57866e26a2e74d1f7d7d19eb16ed3f279dd7" \
                               "f8260aca00a9bf67b8920337720fb80f161dc80ff8fabaaee467fc1a7ba50ccd" \
                               "6b779d0323dd564dc2c37e4e46b50f515243d3b1277cef7b8d58f299889f5be4" \
                               "fe1c6ce75bba7fd22f6cc2f0a62dcd29a113fa27fc2ffb3210d57b36bba22e13" \
                               "173d1b71628d9a37b507a9697865636eb31aa84ac6307aaaae18c79cbeac71fb" \
                               "0b3c9509a23f86a5595466826fc324441864a82ef315a0ed90f448a629e545fe" \
                               "5abb70b4057c447541b494b1bd214638775d72cf26eae52ebd976aa5ad7d13cc" \
                               "3b19d21f1e092f753b3ceecd9ea0d7d69897e72e171be00cc34dff2eb7840c2c" \
                               "7e9613ade22c2f985ad798940d8fe814f5319833c8e1f2b04bced68b86228185" \
                               "360ca867661341a072af8cbf6f599592cb1912597990e323588654f368080278" \
                               "b3159b6107ea796cac4c62073234462b51a0659bcd44e933cc073623a3d2352d" \
                               "25bc698e562f0a698e77a30532d91a9841d4e9ef78a78990c59e7fdfbeefc8c5" \
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
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207a874fedc',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab'
                         '77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual('a6b74e76b739c77c02e3130619b5cd79351cafa313eca344d96967a311d66ee6', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

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

        self.assertEqual('533b739a09115fe896a264b9af3d8074b65064178ab435b71f60ce2c8c428ddf', bin2hstr(tx.txhash))

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
        self.assertEqual('6c623fad8517b7d7c92189ee683d2cc8faeb9233b06b09fca7e27d290859deac', bin2hstr(tx.txhash))
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

        # Test that common Transaction components were copied over.
        self.assertEqual('0102f7c4b7dcfc83e8e41a1acebe46a058229742b8800b23a2d23f3dac26ef527207a874fedc',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01023c523f9cc26f800863c003524392806ff6df373acb4d47cc607b62365fe4ab'
                         '77cf3018d321df7dcb653c9f7968673e43d12cc26e3461b5f425fd5d977400fea5',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.amount)
        self.assertEqual('4d27683346cb197700fed996387b5684345817af1c050d921bda94643d077d0c', bin2hstr(tx.txhash))
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
