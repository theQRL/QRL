from unittest import TestCase

import simplejson as json
from mock import Mock
from pyqrllib.pyqrllib import bin2hstr

from qrl.core.misc import logger
from qrl.core.BlockHeader import BlockHeader
from qrl.core.Transaction import Transaction, TransferTransaction, CoinBase, TokenTransaction, TransferTokenTransaction
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2
from tests.misc.helper import get_alice_xmss, get_bob_xmss

logger.initialize_default()

test_json_Simple = """{
  "addrFrom": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
  "fee": "1",
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg==",
  "transfer": {
    "addrTo": "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9",
    "amount": "100"
  }
}"""

test_json_CoinBase = """{
  "addrFrom": "AQMACCOCpS+LqcLTOtgHws3VvQhsLC/mPG6hO2MNEoCJTDo54cOA",
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
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg==",
  "token": {
    "symbol": "UVJM",
    "name": "UXVhbnR1bSBSZXNpc3RhbnQgTGVkZ2Vy",
    "owner": "AQMXRj3NWBtnm0dU9GxkJRJUiaKCaJTjxCpZDvtoBkUM5r9ScWw=",
    "decimals": "4",
    "initialBalances": [
      {
        "address": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
        "amount": "400000000"
      },
      {
        "address": "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9",
        "amount": "200000000"
      }
    ]
  }
}"""

test_json_TransferToken = """{
  "addrFrom": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
  "fee": "1",
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg==",
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAw",
    "addrTo": "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9",
    "amount": "200000"
  }
}"""

test_signature_Simple = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                        "3c3f3f6ceacdf695b7954c2c38dba8fc1365b8b036e0c4cbd6e7599c0db68684" \
                        "c6612b55ec893be6f189c98e42ed87736e73e2a4e03fdb513f365472a51e67d5" \
                        "b33c44a7521b46d2103cf24f5385894a8d0e4f0c8884a9d02ee83c43c4ada880" \
                        "bca59c4b1d8d7382375b2de39a541c4367a600f109f1a66a4dd83184844a36de" \
                        "9c9bbd38eb602fa0f45bf8db0452c8f8fe05d1956721f8187c4a4bad9fc2e737" \
                        "73b38f99cda52aaeabc57d1f3e7e741144616fff91ffd7c511f62e2980e32480" \
                        "9d8afa8260cf6125fc92a210a7983705358d7b8c7818a767e878e97e5db3c293" \
                        "54a684abbb116e53906dc30f27e41eb39b7ee91f101ae0ea551b4eecd37b0f83" \
                        "3a8cca4ddebd261f6434c3e4f9c139076a260d2fb3b7623399e17eaf317cdd4e" \
                        "83a53a43e7de346a1ddce5bb2102deb2bd1fb12a93c619bb1418544217f0f71c" \
                        "cb658905a96c8c38df5e44ae59d4711c861963f8badccc106d1b6bee1a3efa72" \
                        "f4e94655ccdb71f2c8a53ccefe533eaf6910f7b914cf60938d06d3d754a0224c" \
                        "6525d4a3bf2602ed787adb36bc43863135797bf8c5f25dfcb795a079fb6ca831" \
                        "904f4d8c38242a2d3b1f93153fd90ab349fd651ff27dc339602f324e4fdc98cb" \
                        "5dd4712977e6d05868cc5b2255973854c2dbc122e5cab9dbb84d82407f484be6" \
                        "dbebaa52159fd8ac683314a5039989c9ded97b213cb8e6b9b0b5635956ebf581" \
                        "32b14a0fda7a58f6aae35835a5bda2d5afcdf14eca90b7e2a4554d07ccdbaff1" \
                        "82dd8bf6882196f3c56984da35fef1728023ca4f06fc89e2d4a4d69ee4652369" \
                        "5ca0bde91fb1639f306d857c7c05d79bd46330461873322b16df831b091dacdd" \
                        "861c77f5f70ae5d240f38ee32fe5fa26ba5ae7e4c8a8e885a3d1665c8537b656" \
                        "d1c791a2e26d227bd00c966da00d13f8f195c13fa6ef2e9cd0e930811d0f2315" \
                        "8bd91243a9bd7a247393b9658ec5f6865d31d434196a493576e5854b76d2acf3" \
                        "e8cfb9929a10fef69e6d318f8bd6cc7523b905c1e3ec097d668fbf478b30cb3d" \
                        "2cae1ba4a09cff8338a101bdd4bf638a589ecc5b4dd0332740269e338f8349f9" \
                        "881d9e575904fc769cef0565533328435afa11198667fd1460239f20a8527922" \
                        "6e127803f8c789ce389b93312f23b175fe6234c7e6165f0e3e9d5ce83368696f" \
                        "e94061f83e1a9028d2732b0058616706d79cb9169044072922c8cbad8cc56b5b" \
                        "2a14dfd6cd04b01bcb24ef635cb8e6cbb1538c5940e6840abe606549117095b6" \
                        "e5a504cd13a53eec4564e7919e76da19b51b01cc97f2096c31ae8bf2a46f9b45" \
                        "1b01df57ee9015c59fb8419cd29fc03e2a7274444229c6f69439278e941569d9" \
                        "f21a6e8eb5b89c831c46b93d9a6453f600ec202a0684c272ae5852b2205d223f" \
                        "0c748148acb30e611b766ac0fd6a95d5e64eaa6c50ddddb1fe24ae55e4fdd254" \
                        "5c2b596071c94e3907099dddda5487795a830b9a46d2f9628f13c83790b6fe90" \
                        "3334671474661ee5f02161a3464fefe3499417519daea1d40d8e6c4cdba48f70" \
                        "a5de5bb13f92c5df896df6010091c6d6fdd30621c9ac62225e38abfe6757830b" \
                        "d2019a58d5b57bbfccc1867f9593657147ef23423db76fbfb53bc7a9e4833615" \
                        "c58f3098cb6f5e003d37cb3585b0e39fce3b8551d594ccd77ada1e7dd89890b9" \
                        "293ffef95c407eadaf8872ae2750bac27a065498893cc40c8497117e147923d4" \
                        "0d44478b8e0cbb4301078bc5f08ff442c3c070798eac729e299c257e7cde08e9" \
                        "c9613b277a98bc50446ec8a6c954220a9e3cec65467bcf71cffbaea580cb9c35" \
                        "286026aaebdd2ebc80d12b58164ee6881b799abfa761d920367a985d1eedcbed" \
                        "7dded31e2699a71232e8b04ef0d2d285f06daa2c62c4756bfd2b70b1b116086a" \
                        "1a7667b9d6610809d1382ee89dfbab62cc5c42a6de5dbadf37f5cb7ff342fb82" \
                        "6f81372c2b5707779d1f0a6dc9ae73e46655467867d033efdc324dad08cb89cb" \
                        "8a4d43829788ebc6de0e987696f0f32daa3c7609a1aff6cee92025dc833120ce" \
                        "6e0541086df174aa41d3106e68b30008edcd830bfcc7ecbbf9ccb266ee98fb97" \
                        "7e63a6ba974f48eff9a743e0587ca5c464648cac5e1c08369456c99bad268e49" \
                        "acf4d31d41b8ab2a26b9787ac9f38e6696968b80dada5d63e71e58d4a8a1333d" \
                        "471b91d3f742a65757bb6d73dd029774cdb216dcf6788d4823265fd4f1ab879e" \
                        "196e29c5185db4ac31666477c663e9c9448933842702070518616aa4774e6bb5" \
                        "b5653f83a7b14d5d2a828b58247941191bc84d577237de4a5b63be7821cc73d4" \
                        "364d7b69d762ae79f6486d0bce1a90658a53ea7eac86c979474196f7622b5ce4" \
                        "b5a0d48cfe2ed7c94f79f347018cc15adc23317a2502b2064e5f9970a4296faf" \
                        "bbca7eb613b19cc8c778f790f8a5b754f40063762f92c61d9700bb35ecb4e7d4" \
                        "3d3e70ee77df572e7e1dd7ad37f86d95d56bba6b0589e061a51face85bc12111" \
                        "9bbe34a2941b6226572dda84e3224937c2a806985f8a39b8bc398f84fb48ee20" \
                        "392f58e1d9c8ca20146963f804a78c50ed0f7b3d207046c56bb8e8b881b6a203" \
                        "87d85deeb93fde8d1e1987a61a6cfae9a0736bb1aecda99eb047bc42659a213c" \
                        "995f5ed166fcee962f3974599059f51ea0736dbc2d643cb6136144154e8d9f0e" \
                        "2f5ccef75fc02054d3f568f93093370c6c6ae1fe27b2eb88d62911b7ac2f8e79" \
                        "68c6e078e9d4df1486ec0746f6a22de49502357144525282a4eaa9f55f5efc47" \
                        "d435f2e7b875033859025d4d3c9265614b085daae72b160f471c77f6af443ac9" \
                        "61175698dc66c97b2ad2981369f5b9f391318f33621fd8d1bc43d1fba1a88ba6" \
                        "8d1b993d4a5751194a281a2b1ea7ff51204c7713b4d7bf31e5dd034780305f66" \
                        "87bf32ad6f7e524fc9e31d5400049be470af36b375943d6fd33d4edd6fc64514" \
                        "1d3b735cf9931fcb837d8cc78e039d6a487d06dd0d724bf384046b62652b6f33" \
                        "8ea5004a75de043174eb1cf8e3a1494e094c5583986106e7c0349874555b4eab" \
                        "8896a80ce9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                        "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                        "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                        "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                        "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                        "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                        "98675eed"

test_signature_CoinBase = "0000000b301cf03639633dc916fd972bf6555482329b49b0f54a1e2e56c2059c" \
                          "14c6dd588ffeaea56e0658ee2224bbee4c29cbbc323bab51cc6cb6a48a8e18ff" \
                          "b0dae16281f463875103bd176b1266bb5cceeb6e00e0d85bd1d940b4da144889" \
                          "0ce0cd7e4232c06f071bb850c028f54fdf578de43723b4c3fc9ffd2b07628176" \
                          "09134bb08e26fe7913cd89dd215477cfe221817711e05cb79ee56ea6c8cb3a86" \
                          "567f5e0180d4a07f69e9eb1b6f75af255d1da2463b90417aa39a0c89af1ac9b0" \
                          "752fab7f4a69828247fcc68ab608b24c0e07fd3fc5a4a35bda78440965686216" \
                          "db31adfa52855a66dc95045965a961628b4fefe5c380fbd7eacf3f1503edf068" \
                          "063c850fe322249d9a18deca473e1add657061628c334eaff6e038e81abc7fb8" \
                          "2f30f50536ea7cf4050038099ea217bb69190e9efb60f9a4d54ef38e84aa1d31" \
                          "010f7f096e5cc23b94fea4593c8b9c9bc9cfd1b96e52f8c2787c766eb89974ff" \
                          "b4310ffbec0acd0af42f9212231c59dd61658a4b891aa456e7491269bb4fca76" \
                          "c305e9d58f4cef788b565efc4b23f42657769f1ab2aa6f841282f52f035ae2b9" \
                          "780d24201b87f17b98ffaf7455a6f97d3475a46c8318192403c66730113d79b7" \
                          "173a8091dcaf74fbdd7c347fb3bc1f3fa81c8eff2a40e29f4d617d33d04fbddf" \
                          "34582ccd5d7771787295e6bbb391763609462a85c0e13f0afc65a1b63e778e6d" \
                          "47c1e2b3f9f74c9d6cc51136678b20b3ecafab144cd06107c3c86cd6dfb64219" \
                          "4aa6fdfd17e9bf9e6bb7f6bf27c28544e6c460d33bdcd42ce3ac18e356dea526" \
                          "7e1322d0e43f004ee726ce171884aeb94162a76ce9c94527cf29c6a67220cdea" \
                          "a1810db437cc1f678716f0a8fc4e1e14b93d3e5e7c6b2b2c6dfeaab37d028066" \
                          "8d0add8a5d178640e8ef270cd7eac9e80836312279c63bc43fb8a72f12dafbc3" \
                          "8f5f98d4644d9626930c2443895d9857da8524ef9f048576a4de3fed44e3d6c5" \
                          "5ee964974d3becaa5274348c7de4be34a9dfd082e85cb7b68622d8c4a8198666" \
                          "d1a7d8ee0c250faf4291fa6e8bb7f693f3cf6cc9e7bfb9afcbf074cb94640909" \
                          "c5de269bb15febb4054df39cbc8e8f2af1bd8a6b0da2e1a19142261a33491248" \
                          "85b9ec268e6690d530a14bb7219317cffa4c36409614001361afdcb582ecf88d" \
                          "1fa71c3247320ebfc2e1da7da848440eaae824067288d990b097b4b0d56427d7" \
                          "8be0595a98d9f36964f737bf00e7e1a7c4c0ccd3d0ebe8eb3f4b9f00b6771b73" \
                          "7cab0c9876ad91d23e85f893ff48fa87afd6a63bf764e9f633bec25a5cf49b49" \
                          "1b769d8daccf181c62f52cc61abfd7d29e05bf7ed81d6e08ecb4238c410d6ec6" \
                          "834e754f58a04e72cac8894f7bb0f190555f6a46879bbe71765b4c969faa7ea5" \
                          "4cf3af59f8d99d24c49beb85e5eb9d9608030eec1443aa084168d5b675aba451" \
                          "c7ce717ec3e71d1c2ab398bb03d3f95cea11aed1d345731107fb0a952497f150" \
                          "ff65e51983d517667691217ff2de7250cd0fc0dfd1067304a64c13bf59a8a09a" \
                          "cc23d35e5ee96946c2b4d5296d43bf181f6c84c9af29c2e9dcca0825d1fe6a47" \
                          "9da953206f5559d554778d425a547dea0515db8bae0a827963494fac698e1299" \
                          "ecf3c2e7b771366ea38d1d1490e66baf7b5d7b3789ce75e468a7ab0c38d5ed98" \
                          "9261b523bd607d6b8f72d4483e441aff179cb1fd1db5b9dcecb1556a7f828273" \
                          "e7501ede87fa2f0428ca1b8302c1cf6f0cf4400be6cc3099e3a975794fadc523" \
                          "56db864d1204e7908848bee1c78bdbba0b4634e3b0856b3694a229d15a1c7bc5" \
                          "18143947524e7d1b1f53b550b4d24deb10e49f2ef18d46c637948d6beabadf5b" \
                          "edc3be650eca7953be097f6c08a56e6e325bff60ae33f1ed8b52d5fcdc521bc5" \
                          "c5947493c9d4c51dcbf1d0476f20f2bc68d60936be33e025471709fa497ecc28" \
                          "714ed35e06fbe7b5d94f97fede9fc9a01f096d686bf2d7c0a7c44ec8c3539fd1" \
                          "b0863bd017d0611ee06d5b4116fc6449cd260a8164fa304b15d506759c6c80a4" \
                          "ded85bf7c8cc28b89286fad51cf2ecdd058ba6a64784dc15f749630dc4ce7f45" \
                          "39ef243bf9a8ade270ee7dda7eb8a863aa7b98a1898dff038a34bc6bb17dbbae" \
                          "50f1103203e95ae2120d59a25252715c3105488eb63c99572599859211072734" \
                          "f8ef3d152831f6c91b638728fff37f8f93901eff40d07ec8796bfb2b62a7f36e" \
                          "fa2245753ef6b94b868939affd3f9064632b919a22b51295d3544f217b0ee7ed" \
                          "44c8519420b30e974fc89ba480ec73581f1b129a8b582400dd1d259cf066774a" \
                          "c4e84ea9efda290873c1777ae68db80e47d54b22b6a719321fafe0a4a318a9cd" \
                          "b8efda177c182921e6f3605a19e7da5ec8a9566cfce078a43401731645538d31" \
                          "2815ea88b7d06b264d87c075ce5b0630718c8aa4175e0f95ed92c5f2c5c782e1" \
                          "3ec4352aec43021a22650469ce995567e23dbde8c0ebb3fa73268b427d4a910c" \
                          "33f4ad675aa3afa570cf1963221aacccbf256a2a447f0b30b3394945dd424621" \
                          "f957b87f171bf3dc857db989ad5f8afeac0850d49c84b9304d31e67d05a3d001" \
                          "b860b8fc57745920ad8954d0ff0cfa87182a97aca492b1ade610cb95727b5328" \
                          "312cb3edbe3e3328b088a93e873958be49dd6718354f122fd8b499a9033e79ea" \
                          "619a381b63b53866258711371eea0ab15aa6116fd8667e627b97b28e2b99b6e5" \
                          "4dabb71b92433262f0eb4d43bd9299bd32860550fde0b53f475b4e87de43fc72" \
                          "756bf178b5f601942fe435cd708cc852fcb873830d1e8c593bd21399a08fa533" \
                          "728a0a8737f4c2b1a33617ce6649517dd9707c4f904e0017460a33e2be828d85" \
                          "5837ab007118620325ba4bf00623882aff5d45c4e618f55d549808873362071b" \
                          "1532d8b6b415b2cb20de63d646900944a6a916f4c68d525c06348610832f2bd6" \
                          "f93122127062d2f7ab065682696c99d7087936ea2703fed889dee602238a143f" \
                          "299c3a88af5a2d4719ba4d6a5777242747914de1d37ec4ed85e7249a9549b218" \
                          "74c60350a25b5a4f8544101c2ff672d51e66763997365dd2592d20df8cbe47ac" \
                          "4d658c9704a621417fbcba8108d0c6951d4873c4f36d09a1ed52afaa25c5ad28" \
                          "0b33f12c8d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                          "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                          "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                          "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                          "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                          "98675eed"

test_signature_Token = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                       "3c3f3f6cb2e56f06c23ce4fe206b26f7c8c213c0b83405395ce087a071ab4f29" \
                       "15af977fec893be6f189c98e42ed87736e73e2a4e03fdb513f365472a51e67d5" \
                       "b33c44a74c1ce22eac70a5a569fd9141ec35003339b6d3cdc6905c17e06505b9" \
                       "57a5764870f7693ab3294841fe224c9f4de5c6865e2417a9ada2aa9581f05545" \
                       "a45fe6a2bddc9848ba56a982a0604335436df98a050e6a975d5b3a16d6e8adbf" \
                       "eabe5e007545c6ef354138669b715701ddcbadefa96e94146045c7ac42e275aa" \
                       "80ef63592d1c1eac26d137e6b395b3deec26b1e66b543cbcb261eab981f5ac7b" \
                       "e9d210fa1140c7ee3878e851f470607cb2ce124708a27acd4f4f01611adbff19" \
                       "6747a258ee4c273ceaa79aad7ebc2132896825bf3991bbf99ed4900a0a7320f0" \
                       "b15543938dbb879407332237b062106caa02a8df7d5f41caa34e9eda3f6923b3" \
                       "49137e9d8cd790e10ccce767ee7248738376c254ce6527d864b64e8902344f3f" \
                       "f5aed9f466b3786f2b72dce9914bc3aa97e79727bc51f6d0dd289b8cd0daeba5" \
                       "4a29bbbe68869790996aa6126ca05ade9c7e1328e6d5e07ec5142ed7e429f67b" \
                       "711b7bc36d6f52a2499a97a278ace169e897f98260c4342c9595d33897b838fe" \
                       "4a320f421216ebc8c9f77088f2f0e84dd29f563b5128daf6864e170a3e9d6c63" \
                       "d67617b1b6ffffdc55c74f015c0fd2881063c3c8d42d2f4a4bc80c029ca85ef2" \
                       "118cea74973866bd41ffc6a9b7fb3aff011b9b64df7dc361740623bce15f0336" \
                       "09a2a21c7b53c3de9c98074d72aa21409a7b4e87102909545b08d431ce8b4c7b" \
                       "e56ceb667128edc9c4190dd50187fcd9d8045e4d38b4df4ac67e6225b1abbc3e" \
                       "8373eecce78275b654b3037648d32ea8a99f0c091d85563be382101988cb7e43" \
                       "59510de42d3c9f0eac99611115c52e002470e43f95a1fa7b666263eebdc3433e" \
                       "68be9534c2552eaa461c93911102075ce3e10e1c4bad91b2bfb961e31ab8138a" \
                       "863f0e427d12dd2ab248887b4c1973e7431921b2f61abf16ed22a4b2e0189ce6" \
                       "fe304c31ad2b567d70aa0f2335050bb36f6dd98d0e5695e5ef721445f9d099e0" \
                       "95e745c413e281cf3bd0420c2ae9d6c6a4a9caf9c68c9c26a114c1deffeb125d" \
                       "8c4f671801f3129f705ec5c39cda0a7dce4616631b044089645245caecec689f" \
                       "e59e3efbb21be4bcd6798ebb5385bdabd1533c40a02ff57d444ca4c0fb23681f" \
                       "c4c20f5077a4f5aca261ade1d3d90fe0ba07095698a18903bb70491e80a026fb" \
                       "6892988cb4fde5fa792add4d33fb304a82a2cd128be53907a5e7daec981188f4" \
                       "cec43aaac4f291c54c0e2e8b100579663f61fbe5adc5e2c4e295244bd58e6e75" \
                       "b6df3284953de1640f706c060e3b92e259e829752e42e70dea78e04e1ac9c5a8" \
                       "74a77d1dde86de79422c3807450c990ab080f07d76f46935475e3d4a8ba2aa72" \
                       "5865afc343faed29aa6537d3569015990e85e40b449d2757bfd99a193a6ed0f9" \
                       "5832c1ff03433add23065e774c3887743cdb8b38807c292436a973d6aa235d0c" \
                       "ff3a872d31c088c191d0d8c83e773a1d7778070300e1fd02d61db96439a3f1a0" \
                       "4fbfe610da160aadecf19deff85ae4c671c7de21cf7d27d6595616718eb55ad1" \
                       "f8961a721efc7503c9d5bc6779be6553c2afe2983a26476838567996e4ef89a4" \
                       "6ef1c63972781e487f13f1359eb22eb024430c00e51b1205630de20c591000c7" \
                       "6e7116208e0cbb4301078bc5f08ff442c3c070798eac729e299c257e7cde08e9" \
                       "c9613b2731e19d10e881da3fb6a3b096a950d5e12c81a32670def7f0447671e7" \
                       "2bd11beea12901248fdaf64abc683c4b5625eb94300a4799f7a9f4f3d8a385ea" \
                       "31508b100bd64b91af890e3f397a136fdf5fefefa183483b2b7661ae137da071" \
                       "0f5617b9d6610809d1382ee89dfbab62cc5c42a6de5dbadf37f5cb7ff342fb82" \
                       "6f81372c2ca665c0b5385bdd8fefe8e36476a1148cbad561c043ba2589c4657a" \
                       "badcf120fba552ceb74b5cf41ccd396e248820b87694e7ed0c52649a3f619909" \
                       "69b067554c01bf63fa035256e06f67d95e9c67ead1e636621662ce35d27b9e08" \
                       "32676898080fcdb9d01851cbd8b3986edb072ceb3e86cf18d01b52bffc2ba338" \
                       "a8e4f8a2ad4bb75597a79ef945ad5c3ce87bb162c067825f59d4b55955c0bad0" \
                       "2cad3b12f742a65757bb6d73dd029774cdb216dcf6788d4823265fd4f1ab879e" \
                       "196e29c59ddba84472515f380f468a9dab4bce3cc562f9262309f9af9b0c532d" \
                       "a64f0bd11ea5cf5446ca4c064782e85cfddabb49dad1506071339e2e803f9be2" \
                       "db0241dc9af0524f8bc3a154f53a54fb046cd9cf0df3a45d129adb641ba66b25" \
                       "d9d99cfb357db1c45754ba35248eeaa9b227e56e95bcc57df98997399a29012c" \
                       "5db12362584f15880a0ca48fbc856f06852853d334f1f328be8dd9b52e2f9f3a" \
                       "d2e187efefb4b2fbac9ae2a5034228250540dd0f59979fff5159dc8a81e371b2" \
                       "e241532556e316ccfb89d26dc9012461bb838f90e179e6e08ece20d97ee60a1c" \
                       "576fba5150f979a070471ae65aa4e59d23dc93172eec2ce6dc9b33332c34bdac" \
                       "8109757eea2a34785f4e3e5ea51494664b63b746cbabd00231523950ff0b674e" \
                       "2a8dc2686535389e32365aa25592e1fcae9aacc5d48ea15d8371a5d33485c808" \
                       "8f5f67f16f6d7c9fe80f6534f5af2ced1631ae0c593854430d84e3fee5ab914c" \
                       "ccff1bfccdffaf795c1e6a1e9245addc4fb470bea0e887cbec818a6c049ee83c" \
                       "520d2e80c4e8b7f4e2d2e310a02efae4c2372d471988716113c210c3add4b131" \
                       "6c97af6b14fc1e54bf406140ba03168a397eb13748bd8e10e04bf57232591c61" \
                       "de113532c0f1b107fde051865326c1cbe4c71f26d7811e432fd94ed8b68ea3a2" \
                       "e4f3c2426f7e524fc9e31d5400049be470af36b375943d6fd33d4edd6fc64514" \
                       "1d3b735c19896747b40b2ac8d5718e47387d88069cdc36fdfecd74ce4a4102b9" \
                       "25078065af74e4e70c0f6416d834d50a9ac90be8cfb54eedd18f3e266111b5e4" \
                       "8569c066e9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                       "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                       "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                       "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                       "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                       "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                       "98675eed"

test_signature_TransferToken = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                               "3c3f3f6c33df5309b615f378a281e9d8df1cbae48d42e0649e48cfad99c79cfc" \
                               "acdf160555101cc7c0a7ae3e420fb5cae586489f0615fab67f1447cdcb88ec47" \
                               "6e7e3df7a6a2ec4dff4bf2f5f5c3c4dfc4d876821f8be4a2068763687d266951" \
                               "ecfc8d66b7610252fca1f2bb74c7be9e0b7fee5a97da2bd0abb03dc7ff27689f" \
                               "172d6c30099e09752c2091c16a6edf0b7e24faed1e0e2b26a72d05e9081b6adb" \
                               "d0975fde1ca3bfd0fa674bff62a260046c7f1438d848dabeaba22f19313fd694" \
                               "43512fc3786b5fc65ca94b4c4cb540b585da1741f2d8dbf5bfa52a58d6675b11" \
                               "a8a0473dfaaaf67704068ab8d3a9ff67181b179f46bd580284e7e453631d1b31" \
                               "97b24383f01f37fb5e4ed28ed95c36793021c3679b3e7d1b08380ea5f394be19" \
                               "f96d900f2146c5f7e49a998363da5e6914cf6304d27ad3fea113385c81983be3" \
                               "736258b885df2ff582aaa58cac02d7a6b8c13c655619f04bd95e7819e9353f9f" \
                               "c727e023f1cea29f752142e14197809ef949bb1e2d51a069303eb3d688d9fb23" \
                               "249eb959bf2602ed787adb36bc43863135797bf8c5f25dfcb795a079fb6ca831" \
                               "904f4d8cb73ca1958f83febb53cccd3b1b3767ac9d18a9446817ffbfccc7ebc7" \
                               "dd33e187ef4d5216d3c6ef831cb0c48028b836bd8a589eeea75d965520690c63" \
                               "9c6e49d821ce135ddf65c39f07a598f6d6aefb75ab511b18b2984d5afcb03ae9" \
                               "138bb0b456f7706c6950f7c2e521388eb6e99d2446ef346259a13ce06dec1189" \
                               "91ee404a882196f3c56984da35fef1728023ca4f06fc89e2d4a4d69ee4652369" \
                               "5ca0bde91fb1639f306d857c7c05d79bd46330461873322b16df831b091dacdd" \
                               "861c77f5dba5941e9ca4683fc2a59b0f0b5c50f031afc3b229978283074c6043" \
                               "f1c1b9e6960c799275dcf7d6214442c00be2b7677102f61a2ccce33942a1eb47" \
                               "2b8c0d5cdfb43c17896be01c90959b81b3c43ae29ad99e83ddda8a8506b4686e" \
                               "3340d3e765d86a2a8401b8682566dfb143448e6e6f65abed7cb343dcf3ac888d" \
                               "6136c7a586be408a2a881ded2e8a3534ae03b07927083b8087891d54c12c54c4" \
                               "b4cc9dbdcd66230cc66762902dd7c2c103738c6f4d3c263509b817bda60cf058" \
                               "e93a8141054f997618658130372ea40e362a909099b435b7c323f8a4a678fa89" \
                               "d3745e05d1df13ae58a8637984f34b83dd1bed6fbd8d47da000caa426f5d2f96" \
                               "05a79c0bf1f6cf67db2606ad48ce125eae711cfe8b92a85b23322f2875475f05" \
                               "93356ea1f69f7101567af0bb381c033efef8a9137ae70fb3c05616cfc7bdf517" \
                               "701cac3156f7daa2e11c89e66e1e13458a6e45449e2735129fde9065c010f76c" \
                               "aee607d1d578e538ca186990b9031cec9f404f822da816bf14e5423d3fa57e87" \
                               "3ac899c8de86de79422c3807450c990ab080f07d76f46935475e3d4a8ba2aa72" \
                               "5865afc361f172d265021d6f7f6c71034f8b1b72525c9dcd875f50c7b46c3cfb" \
                               "7cc9e135d31c949073a0388dd81a9018c65e0a0cf337222d6f824fe92e9a286c" \
                               "c6b6783e889f6b2c8890c8fd3a38479a0cc892ee0a6c6332f74b21823f63d106" \
                               "d80d5eba0a1ad11bd72d855c1c8fcf4b779632d47be6514c8ecd1abe75ec84c8" \
                               "5b12f9e04004f76d259d75d4a15a151942cc41f92cf8d2d8b14c3f538aad3e72" \
                               "5993a90088473307c743c3803fb5103544c3bcec638aa0e608211d6155d401d3" \
                               "ee3c2f830c7a84744d291a259b6a44d739261311f570bd2721336adfb5189a8a" \
                               "103a928e31e19d10e881da3fb6a3b096a950d5e12c81a32670def7f0447671e7" \
                               "2bd11beead5bd936361c271d1aaee3645517ebd0d6f7e43546850c64e079fe3c" \
                               "6715b6d557f67024f13e1707bf50189f6925812aa1553cce8055a6707ee65edb" \
                               "06b607caf4a67afb1ae8816e5be95120117ba079031fecd4840eda1932f6a5f2" \
                               "eb44e78410bd11732dca731b565672fa43d48439451c2fea6b898c9ca604ae36" \
                               "683854e0949d387d5b70adda5e2b0456931e26ef2d14edb27133c86e7daf3a85" \
                               "8b4e04d055eb2167664d7e29d8a65647bde1cb81ec5f754eab732a6bc7942281" \
                               "83aee9e94bbb2dc83721142a89d162e65e9a875fd71422911c9da9fd61fdf61d" \
                               "0ac6dfbbb8f3a1062ab65f2f70441d216d61e0eea7ba860ec539376ae0899f51" \
                               "e784efa6f742a65757bb6d73dd029774cdb216dcf6788d4823265fd4f1ab879e" \
                               "196e29c502406e4c6eed081186753cfd6274876748dac65fdda4ef154a31e83a" \
                               "382203c00424e37be7e9d0ddccbd691992429247a75117cb370dd6bb20e90397" \
                               "c679dc6ac1911bfdafb8c97e2fcd841f9c0b34241f4a1669776cc48727df459e" \
                               "30e65ed52f783d31ded44d46a9542f9f4a9d5b3e42ff86c100825aac5ee7cce8" \
                               "67ae919869cf1b6b382d0bb58fad46463165a723cd5b65d4e70058fd1c9c6363" \
                               "ffa5d170efb4b2fbac9ae2a5034228250540dd0f59979fff5159dc8a81e371b2" \
                               "e241532549203930b347d73dd8003928bcc0bdbf3a1509406f4f6a3c31e8f7fa" \
                               "eb6b3cb3c174746b3155dd65f4b5b240621f186092f30bd3ae5cf98c15747a47" \
                               "67c87a53b93fde8d1e1987a61a6cfae9a0736bb1aecda99eb047bc42659a213c" \
                               "995f5ed15c11fca0c64f656c2d1be440e38e69b43861da085c1ad3ce14d869df" \
                               "cd35895f3807b3459b4b4130b261eaac342b298d884a1696d5253535d96923ee" \
                               "00359ef5cdffaf795c1e6a1e9245addc4fb470bea0e887cbec818a6c049ee83c" \
                               "520d2e802ab87b9cb4f3367ab21c281f12372c68bce06fe71a3d60216c6ba3c9" \
                               "1d0bb3ec08c38786bc744eae48e3b176a22bed380d07c605df2042f177b0910c" \
                               "d143d77879bc7a59f3fe4e2e10a24e83876268e83883a243b84d9a176b1b0886" \
                               "8c3b0a182111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                               "9da0ba07490d2d3ed07005a0f9137b3a7baf47998f4ec34697a39450b425f93a" \
                               "6addcf1caf74e4e70c0f6416d834d50a9ac90be8cfb54eedd18f3e266111b5e4" \
                               "8569c066e9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                               "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                               "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                               "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                               "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                               "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                               "98675eed"

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
        self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual('40a45f021c1b7fe6871e2b4df83fdef6771e779c65d0e46a2002e689dfd23dc9', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        self.assertEqual(test_signature_Simple, bin2hstr(tx.signature))

        # Test that specific content was copied over.
        self.assertEqual('0103001d65d7e59aed5efbeae64246e0f3184d7c42411421eb385ba30f2c1c005a85ebc4419cfd',
                         bin2hstr(tx.addr_to))
        self.assertEqual(100, tx.amount)
        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        # If we change amount, fee, txfrom, addr_to, (maybe include xmss stuff) txhash should change.
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

        # z = bin2hstr(tx.signature)
        # print('"', end='')
        # for i in range(len(z)):
        #     print(z[i], end='')
        #     if (i + 1) % 64 == 0:
        #         print('" \\', end='')
        #         print('')
        #         print('"', end='')

        self.assertEqual(test_signature_CoinBase, bin2hstr(tx.signature))

        self.assertEqual('5efafcee3af58c57cad875d71841421ab139ade0fde3bb0107e622813bca0e55', bin2hstr(tx.txhash))
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
        self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual(b'QRL', tx.symbol)
        self.assertEqual(b'Quantum Resistant Ledger', tx.name)
        self.assertEqual('010317463dcd581b679b4754f46c6425125489a2826894e3c42a590efb6806450ce6bf52716c',
                         bin2hstr(tx.owner))
        self.assertEqual('d36a6682022a14a3cc4b6d5e79f322a91ff32d8de83730619e2a2b1779653f71', bin2hstr(tx.txhash))
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
        self.assertEqual('010300a1da274e68c88b0ccf448e0b1916fa789b01eb2ed4e9ad565ce264c9390782a9c61ac02f',
                         bin2hstr(tx.txfrom))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.amount)
        self.assertEqual('3cfb7f2a952bf3f90ebc882f0e6f4b9aedeb2d2d4e10b06e057c6173b1e47bd9', bin2hstr(tx.txhash))
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
