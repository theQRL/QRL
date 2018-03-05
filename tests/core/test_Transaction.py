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
    "addrsTo": [
      "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9"
    ],
    "amounts": [
      "100"
    ]
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
    "addrsTo": [
      "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9"
    ],
    "amounts": [
      "200000"
    ]
  }
}"""

test_signature_Simple = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                        "3c3f3f6c2a454fc223c1c6173a51cf6c243fdaacf25f3099d976d70111167beb" \
                        "fc703d51af540326292558f3ddadd208907f575fa783a1f25d9e05de2c0678ea" \
                        "5aba805be588ce819a27523ef24066365a4156a1f809d7a47e047f99888a4998" \
                        "43fbbab789c1a82bc28ecf80dc8079c840d5a762cd867b45a62360486626dfe2" \
                        "c5ea3ad358b07bbe4fde6a9fb6bdf2afbcbdb1343d3000afd32a3267f1c8325e" \
                        "43ee43c3cda52aaeabc57d1f3e7e741144616fff91ffd7c511f62e2980e32480" \
                        "9d8afa822c24d6eac15e99adad04e67a6f8d2d8ca3e283389899f7e579ee7ac7" \
                        "89326fa9f108b93d337842be29467ac93b3eedf8164ca0b6d3a1266a67157733" \
                        "ae66bcb5fdbe6a12c62eceecedc9942c13ab9fb0ae1105f71e48838d1fefea7f" \
                        "eba2d0948dbb879407332237b062106caa02a8df7d5f41caa34e9eda3f6923b3" \
                        "49137e9db38d2dc81ee93e03e285507122239fd0801f878ab10cb87ed07f5f48" \
                        "f628c32974f2b67c794a147e9105e7889f6fbd770f0003b9fe7be1c5a62916fd" \
                        "4ec813961ec5aaa0d6c1a169a6cb78f81e8293cda97bee94865f19fd36104c56" \
                        "b6bddb331cb53f5a95e04fb553610329fe82d30988dbc5686ff1052b7115561b" \
                        "15a36fd3638dd4c3c0126286b5abb0dcb106841e1c24b2ebc430f111e03b0c66" \
                        "78b90a1dcbefa34dee01ad01568b3e552776be5db6c269f437e1e36e93391c47" \
                        "8f021fa956f7706c6950f7c2e521388eb6e99d2446ef346259a13ce06dec1189" \
                        "91ee404a7da6a2c091f82a98cb7ab34c2e49541714ee9f55b3963d7ee8f1f870" \
                        "73fbc5c75e1f86e78b149ac7fe764b326e18404203863641ba9fad2b1a038c7e" \
                        "c1abb0b3f70ae5d240f38ee32fe5fa26ba5ae7e4c8a8e885a3d1665c8537b656" \
                        "d1c791a279cd8e8de151bbb33b60559749d1fed65bc8ca8e0226ecc6304258f7" \
                        "012c872e116575634cc0c89a6c832af31a8198c4d01c586446b85cbcfbe3b686" \
                        "2a4c39402c665dfd27698a6a47f317e3bc3abf0a9fd356133d5fbb3c8e22a49d" \
                        "4b4f5b0442a1498b62c5624d757a648ab82cd1958c67195128f3f7a978954575" \
                        "d8c10574b53ffe8f856f0326cb6876d52e746d9c9445227bddcc0bfb504975b9" \
                        "bbb7bd6f6f7974b94cee4536cdb3c9c16b984d730c90bc16b9c41ee05b4af623" \
                        "e7a853c6e2537e365ae0dbb59a14412e64361f732928db01ee989b2c91d7161b" \
                        "fb9a86a1cd04b01bcb24ef635cb8e6cbb1538c5940e6840abe606549117095b6" \
                        "e5a504cdb57def74ca9397c3bb2811df5214dd56b16ddedefe2fe9f4e183c561" \
                        "7c529af0964e2538e75bc5155d6e3b9e0aac1e68d67b9d2216486fc1d32b1a82" \
                        "3a3cc20ce0cdc0a016968962ad98f6dd278d0ba05eab0c6c5a11bfb6d4ba92de" \
                        "1cd622d5e32ed2751649cd9cdcbdb5281fd21d4a9daaf61d18d048d617e49b72" \
                        "c9d616b57f1c05e783577cae1a0e1ca293a2bcaa8918c6a278af68266b6e80c4" \
                        "0e63468774661ee5f02161a3464fefe3499417519daea1d40d8e6c4cdba48f70" \
                        "a5de5bb11df0e6ba29c66d84b8ad3ef6f513a3c27c346fad17d151b31c75361f" \
                        "a5cb7ddc0e629f6ca1a5c5c5af6d35cfba74527df0d0631b9d0770e20ca73679" \
                        "406e0f0fcb6f5e003d37cb3585b0e39fce3b8551d594ccd77ada1e7dd89890b9" \
                        "293ffef95a87f8eddbcfe0f6bea0aead69f1ca042187946b9720046b46ad2045" \
                        "73ca28996c109bfafc75f7c7885b44f896fc5bc1f4d903f5fb3e79bae04b3beb" \
                        "e9435d02ee22ae61b24d587560c1446d600704973df76d816fb171adbec24bd0" \
                        "969d742cbd85288197896f624b334ecaab844c0c5d03bfbc5ba6dfc9bcd2cfe4" \
                        "1c472c1c551612e2cd572c955c7be9a3ec618c8631ebf2aa4cc5ec327cc1fdb4" \
                        "c29bfcde2dc1b66fcc1caba75f413d6c087477df6f527c7a9b8c7f2b143d2cbb" \
                        "684b1abe4560efd70824938854ddbf8e4aa2d6a414e8925dc9582e2d0cd51e67" \
                        "7e46a468767a9b5d81f2a16ed8ac51d2beedd31145d5d5cb5cc311e2de45eee6" \
                        "6f4fde3d5e0675f3e61e686e870b7fe4a63e13f4cdd75e28735071b93369619f" \
                        "bfb28227080fcdb9d01851cbd8b3986edb072ceb3e86cf18d01b52bffc2ba338" \
                        "a8e4f8a276b1b3c074eac387af02bcb67b7c764ae400ec164e91c5143a8f03aa" \
                        "4985a0e4f8bf725225e7cbea60294bdbb22e31166abd07b9c3b29ee86bc9bc08" \
                        "1637ba101956bc649bb6a5f55ca7c6868b73709287519459b34755eac6c58fee" \
                        "851a991a7e39307b74856452623659a40431641937272de134756d3343ae2916" \
                        "08f507fb76f969d0b534bc3eb3177b858072220e25890dbdbc743708ccdd577c" \
                        "922d54cd43b0d4305038509f50eca607e4f7614341fe198145f9c29e57bd2734" \
                        "0f1dee602762e2f5efe38d602eadf9b4fbb84198440f939e88ad3ef4897da608" \
                        "a2c5e181efb4b2fbac9ae2a5034228250540dd0f59979fff5159dc8a81e371b2" \
                        "e2415325e619c7629086979a8671439f13d5474b36d60852baacf4594c324447" \
                        "9584554b50f979a070471ae65aa4e59d23dc93172eec2ce6dc9b33332c34bdac" \
                        "8109757e72edbce7af3b1f1992b80ed514bc4e176355e6530051a7971f8c2b4d" \
                        "519a79295c11fca0c64f656c2d1be440e38e69b43861da085c1ad3ce14d869df" \
                        "cd35895f6f6d7c9fe80f6534f5af2ced1631ae0c593854430d84e3fee5ab914c" \
                        "ccff1bfcff59272398b745cda30fe82ffa4f983321643cc348a8dd70dbe79843" \
                        "f952848c70fd0c5e4d131487e738a50ed0ff9e96b8d35110503d06b7960c0d01" \
                        "a955d510e2d676ecafec0fda73111c88fb2c12988fe0c21a38d82f943cb29171" \
                        "2c01fb99fedc1b34ec294c83e7ddcaa2fd21dc09b766343cf35032cc0234ab3e" \
                        "3c7078232111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                        "9da0ba079a934ab085b2fd6dd340ec31e77a1aff6cc586730264da3232b3aa5f" \
                        "2bd2a25475de043174eb1cf8e3a1494e094c5583986106e7c0349874555b4eab" \
                        "8896a80ce9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                        "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                        "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                        "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                        "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                        "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                        "98675eed"

test_signature_CoinBase = "0000000b301cf03639633dc916fd972bf6555482329b49b0f54a1e2e56c2059c" \
                          "14c6dd581fc09bfb75706c161f7850638c76ea0e50e3e0c3f3a723699f4980e7" \
                          "48faff5b46c9046ce45be51480aa092ee3c9bc2711113b871fbc2300c3b5a4b7" \
                          "d0f1bbb4130e8170f682d8c0fbde93fef4afa154c1bec8c5e07c227b46f6d3ed" \
                          "61b36f322251455fee02c9603d414cec6a571f5d6580fcffbe228ba6226e1984" \
                          "a710452761021137c7c6fa4c889ea0b1a1d6559c5503d4ffb44d637c6dcc0813" \
                          "02d9c2f97e40b9d6178ee7c187cfb8b719043ba65954b7fd62875282b5dc47fb" \
                          "2cbb47c538be446eca30216731adba1593f10cd3a57f167563cb8ecc58e89ea9" \
                          "560d6afda92973c3caf89c10694b116c247239dab368cce5632f549d7420cd66" \
                          "87df8f019c4132f74e5975b2fc1b36bb5d3b595d72a5f4003c48812ad8e71b6f" \
                          "02f211efc29418051de7a3dc7ec70b85b3e3adcbfa0e4567d9fe1c603ca4a2cc" \
                          "a0395a9dae71cae8572e829dc5833301db8738dcd362fbac1d1e040b9892a5a8" \
                          "38023964e83437fc6bb10d39c72e9e11f98090c4430f9c44861e899c14fd88bb" \
                          "2c4927124dab00d46fc9e1264a0577d3fca7fcd72b2f577ddca29b2e0c53d843" \
                          "f92fc338168e4f01c3fb746df6eac812b4b195c78b2ed63cc69d27e71a7244f2" \
                          "a0a27c542f1d46be6ba45da62c954fed959d9ca0ace661308a82999587b12002" \
                          "d1cdc35cd32d268088c614b3ed241cc268c71662b35d339a297b057f91999150" \
                          "054c877f9b8928805f189838fdb6bfcadf8f1ce5572dc8d941ee5792933c2cc8" \
                          "30c92b74a8d7efb9803af54d6e622c3ef638765d63f66bbbb5e0f88cd3d4dddf" \
                          "985a73f8842d4012506356bedc9fdcf0c32f5ec4cf5d0881d2c5fa9b877b13d8" \
                          "a013b26e78ecb6bc3742287acecdade1c83a1ef7609f677826dcd7fefb54c55f" \
                          "e62935231cd9e55cad2443cde81c628b1b48962b55d9b93d438ad716c5300a9b" \
                          "311123b69fee2ba152417d7ff4c1bdb3abd11601f3197340791a6cd1a0ac8b75" \
                          "a3773096ca250dd03710d1d468726b38b32f3527b05b30d4ac4694b5905fd7d9" \
                          "54a132f8fc1ae24fa80454a425914b9887a31aec8f6461a455c4bd9656c82eea" \
                          "f681651778e93e6e5446c2c241175dd6a9bfdfd4f7a16a491784465dface395f" \
                          "81e786553390bf2fd6d3b79fc3580f24702503120fe13b9990350d7f54f8fc89" \
                          "bd6fbc016f3c82557f5abc08b75d0709e5348aced7afc4152bdffcfdb8411054" \
                          "35eefeae524f3467fe2a9d570cddd44b7699ced8084c400a85ccf383aebbe105" \
                          "50a333cb942ccb5070dd403ba4033edc4bc0858c37214974ad3114aacea3d5f4" \
                          "31fa6772463e20036afb4af3ef4b3c12f14475092c2982dd976995f87474ac99" \
                          "17109af9ae58008524323de8fcf1be16042dcb0e60446b4a6da30eb5c99e0e43" \
                          "3223aa5571ed06c0c1f2e9da5d5ff25d29e05cd996863a356a316b736bc78ba7" \
                          "9a4348b7a450fb64d2a6dc08042745081f163d41b0010c4687588b78676945f7" \
                          "e550afe97b30b62de8815cea92186526ad13bd1e309b34bd45b49419b23502d1" \
                          "4bc2803dbb95eae646c56ef1af5eab9c2255666e3d845152fdc9cea4a0e9e07f" \
                          "208b258b8a2b2499f591bd71347a66b43f66dea81ff8f4fed498ccbb2b0559bf" \
                          "441826cbdbba99680288c02cb09b4492c60c902783b1749f93c863f204ce0eec" \
                          "5c2e976b4a74c76ccbdb6db0737322f9dcfa4ab8bc6a2e0b9d897e623e7eb300" \
                          "ef52117bcfdba72d5201f5370810973fbc0559641edf916a7617811e61984343" \
                          "53ef8a8e9c1d450bd53f6bb03277cba3396ead56e370fcf567cca09af734b7e5" \
                          "a3496fac5018f0fe54500d10f4c748cad6f53fa3f366e02ea36ce3326ee61b2a" \
                          "18050103036abfdb8e4cb0ac837a23cee3a091d58813e450083621d9b3b639ee" \
                          "c5035de50c3caca862918df6cb4d31349d9ab6f918ec6c4de560014f0e32620e" \
                          "04abdc9aa64c763965a579b2e2958e32c20d0c09f19aaadac544e1083dcd00b7" \
                          "2059a5bd962e4df67bdd8ffc8d0a7993a61ec132c828d0b814c45c70b99a8f55" \
                          "ff9eb192fbe92ee043d6a5b9abf7ee50dd8bcf1ea268188717c94390151f19c8" \
                          "5494db0c0b20c845230540fcfb581b54042acbcb2ea2d8c7cc8e0f30bfb9c135" \
                          "10a0c95c888cc4a20cc5b62905d7a76030e8d6c425f9c4e068b7d16170aad53d" \
                          "3ff87bc7087e5246089508d67ca22b1a1d873983817a3721c3918260f11ff84d" \
                          "b5114f2b7d0767cd88a226a967f66c6f81a3afd87c8450d796e1803e0c30fdda" \
                          "5a077c062ea6fffbf320625b0c482dba3a94e43a7517b1b41c63faf1a576a3d0" \
                          "a0efc1752eba4bee627519aea007c51e95f0ef5a039ce3d9f3fc6ce862c2d0d9" \
                          "db6dd5d439fd132f15e04a6dd985a55717f452e4ffc856fc5000ace6b679df9d" \
                          "dd87e9f2031a0d9f0cdcff14bf216f42486da85a35930125d44099205e5c4663" \
                          "abb1cbfe4487a5c698bcde5489506c1769a05af6d2858113da0172b96368bd55" \
                          "6a1e502daa760881de711bb49c3dc7806eaa750a486e564aafc18804c750eea4" \
                          "57174377db98c2fb56ddd0fbb5393ff596e686e721ee4af8cdfe91da4eaee298" \
                          "dca7895cfa2030ef6072cd41731ca08143102972518d45dfd2f100d928489d04" \
                          "b00b374e328215481b269f7c6f709733c0e33f86c34e9618cab2f1a51fed3604" \
                          "85971712c830b879ee116f6a49a23ae67801ed2c6905e9329a81fc94f52c3d1f" \
                          "c2b507c278ea3c08936b06c8fb1c98738185f377fb2ee94f303554c515a33527" \
                          "471cc2a33718d2d237e4110b8cbcaba4e875527c3baa8f025d67599808a06278" \
                          "07d9c2d42298134c62b739d007358e9aaddaadbd228212b5793fb4dc2dfe4fbe" \
                          "fb57eef35436348572e01bf829517be498aa246551466b9cff03755cd95b68f0" \
                          "7f68a9107062d2f7ab065682696c99d7087936ea2703fed889dee602238a143f" \
                          "299c3a888aaf7b7d31214fe12d36b8260a4778b16591ae1f2d8726b934c8bd1f" \
                          "1c22f558a764e484f7f0ce867d9d5e00a9fec19d45152098e479e8869a2be6f5" \
                          "30076f6104a621417fbcba8108d0c6951d4873c4f36d09a1ed52afaa25c5ad28" \
                          "0b33f12c8d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                          "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                          "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                          "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                          "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                          "98675eed"

test_signature_Token = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                       "3c3f3f6cb2e56f06c23ce4fe206b26f7c8c213c0b83405395ce087a071ab4f29" \
                       "15af977f5d8f176dc9d0d5b9e08bf6314933cd1fc630ee0e0deddf477c22220d" \
                       "61b3a78bdfb976a0c1a5875b90807f28a9cc8d4c6b3a8c51814d798433306890" \
                       "0fba65431d8d7382375b2de39a541c4367a600f109f1a66a4dd83184844a36de" \
                       "9c9bbd38eb602fa0f45bf8db0452c8f8fe05d1956721f8187c4a4bad9fc2e737" \
                       "73b38f9910d87b749a72a5836c6a95e6d312bc63ee7f041ebe5778de1c5e2eed" \
                       "7e15adc22f196a4f3d5ed2ef017e601b5e108f19ae5a98871131c9a48a762298" \
                       "0e5aae7dfaaaf67704068ab8d3a9ff67181b179f46bd580284e7e453631d1b31" \
                       "97b24383a822d31d5b8d84e899d28ffef2fb678607b1574a8e6324db4028076b" \
                       "e959815ed917836bf22c3b20a4de1449b6e25268fc4b730c2ef6db4789278404" \
                       "ae5667c19c139fb6bc10fe2fe9ec81db10c61d7c83b8443cd7070a70d1a22c37" \
                       "07b7e4bb04198d1956137f1c76408e2c9c71a8141a5ce2f10a836b5187e92d33" \
                       "615af8e43097e91198419ac22516c74cfaa5ee5f72dc628710da0d2bbfee30bb" \
                       "1cab7c94b2c0af26da5ed7aaa55432105af81b51a3b611312b6d769fd556dd57" \
                       "89e363fd05c6348864fd1a672296bc4af9ae5c35199b425b6630805513378321" \
                       "ef2b4f7521ce135ddf65c39f07a598f6d6aefb75ab511b18b2984d5afcb03ae9" \
                       "138bb0b4da7a58f6aae35835a5bda2d5afcdf14eca90b7e2a4554d07ccdbaff1" \
                       "82dd8bf6f0138c49be4928593b8cd3d6d67cd70c11cdccc29743a42a57c84c03" \
                       "b88f7d047099027169e2c5b1cc8192d28b4b931eb4529504702b3c1fc667e0c8" \
                       "ce9a49b1ae89ec1c00c2805c0615cfccc2dfbb47cfd6340478ce75955e93b16e" \
                       "a0ee11b779cd8e8de151bbb33b60559749d1fed65bc8ca8e0226ecc6304258f7" \
                       "012c872e3f9dcb62ff95a08b1e66f419921b1ed60ab5d7f412b234f5b889d2fe" \
                       "0c1ba52dfb56b38056bf3e9843df382e7438d28fbcc7e71d0996e3cf21af7000" \
                       "9f66ad7e76676b646da613b9eba731f7aa0a105d20721aa01b4edadc449bf50c" \
                       "a9d57d0178041b1c563dc3de516f5051e56af464923d77adbd57fcc2dd286b4f" \
                       "75da96c96f7974b94cee4536cdb3c9c16b984d730c90bc16b9c41ee05b4af623" \
                       "e7a853c6b21be4bcd6798ebb5385bdabd1533c40a02ff57d444ca4c0fb23681f" \
                       "c4c20f50cd04b01bcb24ef635cb8e6cbb1538c5940e6840abe606549117095b6" \
                       "e5a504cdcec67a0c390447b280a22d7d49d448be797a893a3a61e4bd5e5ee2c6" \
                       "9362951e6592024d72abc1fe2665889606fa4d16a7d9818c3bd6d397011d51f1" \
                       "7963ae2b6c9015dcf201bf91451d0d69fee85a28d53d9e422ef4cb4e70fdcca0" \
                       "fc7a7b3901ba9a4f29cbb0f1637584e3e30fc87b2d27b93d4ddab0bea7278f56" \
                       "28962a8971c94e3907099dddda5487795a830b9a46d2f9628f13c83790b6fe90" \
                       "33346714bf055788c0e851cad41507b06f873e3eaa01cc53e714af90aba79395" \
                       "9b3e21dbfbc8596f469ff6849478a6d26c86c13ac24abbc501781b42386042cc" \
                       "7d0b801ab34ceadb1cf5f7fa930abfd68b0d1083265450a1d02f3ab2cc2f6fcf" \
                       "39a516d6fdf56441b82074295c2cb0fe0b7afc3bd58f217eb0aee5d6fc265ba8" \
                       "c459cc95707915ca30462661c952ada36b3383e73a5700d13edc9cc9c083b307" \
                       "8928ff886c7a77177a124f98396b4c74752ff46e60b881b782087e7f0bccf0b8" \
                       "a07d3a4023b0eae3539e266268e3fb12557329d2e9b6f6300b3ef01480e0eb9d" \
                       "a50ffb90bd85288197896f624b334ecaab844c0c5d03bfbc5ba6dfc9bcd2cfe4" \
                       "1c472c1ce226698beac330e7116331887970c6f49cd68b12e27a9f03296a6120" \
                       "0a98edf79576905bdda2cf74f8a6933c6b255210ce34985986c3fb9bfa581dcf" \
                       "e05d6822b9b1e4ee22b4602b1360c30888a898ac43fcec032b803972a9e3dd11" \
                       "bb120e66707f4908432a722daa116faa11f74d076d022df1fee44e1e40e330c7" \
                       "b1f45f0955eb2167664d7e29d8a65647bde1cb81ec5f754eab732a6bc7942281" \
                       "83aee9e93cd6a756c5b6d491b47aa9014a7dee5b2a58153aec7f4faef1a1061b" \
                       "d1936c7447929ef65a1424b5fb07d094a8a98a09db01db22bc6c5cf1e51d9075" \
                       "0bc8224594322068041ce769f59760ffd593a2c97d04cd1fdefcbba79b7a7fac" \
                       "eaf15952793660008168f02111d0c641ddff84839a9abf1bf58ae85633cf210b" \
                       "ad60dce64b54e576b345e9301f4928ddf1eca2dabaa2149a92d4a0717e35dd2e" \
                       "d90f63e87105ee77be11babd87ad456c49ba7d8fe2ec50141133d3e420f0a6fe" \
                       "dab1a56cfe2ed7c94f79f347018cc15adc23317a2502b2064e5f9970a4296faf" \
                       "bbca7eb6260ed9a9768850795765fdb2f275743d785bdf365371adedc1e1be92" \
                       "b9b6fd91c07922d4cf4b3a04acfb552c502f17efc652606009fcc255ed89af79" \
                       "d3545f1f5a3035b8f6cfe17ba9dd2f994e98a33a3f0dab3f70e53756bae5c548" \
                       "245f8abb50f979a070471ae65aa4e59d23dc93172eec2ce6dc9b33332c34bdac" \
                       "8109757eea2a34785f4e3e5ea51494664b63b746cbabd00231523950ff0b674e" \
                       "2a8dc268d3d9d70dfa414483b4a35a839abdde83b541f635d12427ab67cb58de" \
                       "5895529b683b7decc18add1ba750e5d6950d4b54f12335fbb29f1c7e438ca5af" \
                       "62720f2c83aeabfc938e84a1ad4d8adbba6cef1d9e0d249fb56dfc765b4623ed" \
                       "df009e5137e2e95bda59ddded762b4e5a2e7bff1dc5e280d0e1e0995e1b8ef60" \
                       "2b1248544c9ca96cc7971158742b3a5f203e5cb5c6cc8822d0ff646de32a562a" \
                       "7c7a5f1dd202c5242bb328cf7136221456656fc81d0a375c844727874d5c0063" \
                       "e1f768c02111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                       "9da0ba075e59a7d9db3b89a7f348ceddc3ba47e6097e56a51d8672902b1bd7f8" \
                       "bf94877175de043174eb1cf8e3a1494e094c5583986106e7c0349874555b4eab" \
                       "8896a80ce9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                       "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                       "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                       "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                       "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                       "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                       "98675eed"

test_signature_TransferToken = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                               "3c3f3f6c33df5309b615f378a281e9d8df1cbae48d42e0649e48cfad99c79cfc" \
                               "acdf1605b9f17ad396aed963678edeab3e6e35c082ecd7bb8ef568f2da92fb2a" \
                               "7336a7d54c39bb8f16fd92b81b921376cfc752122d0165f60ea1c92b9a042669" \
                               "130bd10489c1a82bc28ecf80dc8079c840d5a762cd867b45a62360486626dfe2" \
                               "c5ea3ad3d5c2e1958f18366b455b1f606eec2a52ea2106c7dac9c40015544ed6" \
                               "406a892d0b3e97f529ed567452a531b3c3f922eada0222c74ccddc02f404e098" \
                               "e66c4063f7326dcf2f564c92480ff19ec6699c3dce45f61791dd60cc5285506a" \
                               "67d408d8f108b93d337842be29467ac93b3eedf8164ca0b6d3a1266a67157733" \
                               "ae66bcb5debd261f6434c3e4f9c139076a260d2fb3b7623399e17eaf317cdd4e" \
                               "83a53a43a1291fd3954c09b58e2aaf73f1b56d62d63a397d31b8982d81ecd4d2" \
                               "14474d87e2aebe38f657e78da69d9ea763c3e641ed1577822d25f46bd309d41d" \
                               "b946c42b7efee1854be94768ac194537b262cf26384e5d8a6e6b856c38e66401" \
                               "c4916e94666c03d96b2fd8e938fd1a46189d0a8ac5054cdde594a18fc4c2cf1c" \
                               "fc7f43303d0abd08bcf62a7337cf9c016dc98697820f31d186eee39a83409e12" \
                               "33cf1d456475e5d9d325092d1572b9211df2a1547ea08d49c2d3b6441bb89c38" \
                               "db466135a0366f944af2556931a315f337b9827d5f31c1bfe553a913917297d1" \
                               "23c0ee5ef5c003bbea31917f7af25b2b83e1f6cedd51d3a789a180d4bafbcd54" \
                               "ff6b217ee0dbc9a8b8d80f690d200a46b433dc775df902647fdac9e9621595f1" \
                               "b0c86f069e7823a14434d617e3d55a24960febf47e2bbb26ea6db14a94e6cb4b" \
                               "42527f1e4eadbd066f9d681b3aea33cfdc622a9d7946760f58bca67281c28623" \
                               "65395c8b960c799275dcf7d6214442c00be2b7677102f61a2ccce33942a1eb47" \
                               "2b8c0d5c667df70eb9b82e99bf11abd06b07629becdb0f707f2f1d689d2679b5" \
                               "e50577749b721c43a720f9ef6ef9e50eeba4e148a7b59f78773bd068ac65ad71" \
                               "9b4c8a8aa09cff8338a101bdd4bf638a589ecc5b4dd0332740269e338f8349f9" \
                               "881d9e575a10a9c8651c08ffb0830b175e6200fcd812cabdefc0ea39d82bbd79" \
                               "82d43e4b7cada39ebf9e017579f78b591be0919052e04b21ae7bd06ce3ba3363" \
                               "7cea93c75ee7c44dffe932c637ed9429d97c258cca2816da02497ed7a121e093" \
                               "5025037077a4f5aca261ade1d3d90fe0ba07095698a18903bb70491e80a026fb" \
                               "6892988cb57def74ca9397c3bb2811df5214dd56b16ddedefe2fe9f4e183c561" \
                               "7c529af0b1b68dff2e119db0f08d1c9ce82a3c13cc89a400abd750f5dc92a19b" \
                               "2d2ed2e3e8c1245a2a83fa1e1319dec769ec51f57ee3c9267f04953ca64f3f00" \
                               "2c1c235b97498ad0084139243cc3b553a38dde0855c5d487d8c4ecbaebf75186" \
                               "e40deeee43faed29aa6537d3569015990e85e40b449d2757bfd99a193a6ed0f9" \
                               "5832c1ff2e132210d2d8c599b39aa005a7ee62e165c1a755f32050957244a33e" \
                               "9052c22ed55998dabc778f738c2edb7b22b5ddeccdcc6fd1f194ebe0db3d2f91" \
                               "c384369e5e7a93b2430cbf30fc3a51019aab82e73a4bb6c7ab32740daaaacf20" \
                               "bfdd093ffa01079f2488fa794f0bb06291d2ee35c101d98fdb444ccc962b94a4" \
                               "7aeef90cbed815bed0cba6d59cd639958269338dd3bfe2e7e82ed50d32124292" \
                               "493b42e0ffec01bb3004d9ba9819f3b3545a4320ba8f26c4bdb2e50cd0c7a1a5" \
                               "dd8e9e0d0bbf7001b2afc09095f582bfa5cca3dd0e88bb4b07795e719ee3ce34" \
                               "29fd8762a12901248fdaf64abc683c4b5625eb94300a4799f7a9f4f3d8a385ea" \
                               "31508b100bd64b91af890e3f397a136fdf5fefefa183483b2b7661ae137da071" \
                               "0f5617b9db064452823e6c7b38c3dc8bd60873e9b4451c6221799112fcfb871f" \
                               "509c3fbfdf42e461de58255b5f6ea3b99d40fc75063b4c307ea3982889242024" \
                               "af39330a767a9b5d81f2a16ed8ac51d2beedd31145d5d5cb5cc311e2de45eee6" \
                               "6f4fde3d5889f83db2e937e48927c39e2cbeebefe4e52e0ad4cbca9acc7ee7ae" \
                               "99a84e76158c8d63275bd4d7c395fd50bc6f80779165fafdd4636537d061b316" \
                               "55d7f14eedcbfe47f1b5b2c8a57ee7aa079ffe1293545bd380515b5b92fe2576" \
                               "82adb63f3c3a825296e2330246d27b3b66cf6db99c87403d372b1f2e9ece2d49" \
                               "cad96146185db4ac31666477c663e9c9448933842702070518616aa4774e6bb5" \
                               "b5653f83ed704b98913862c3b2c5e90a8c9b725597cfda39d9f0328f8e2da381" \
                               "a3d8c4b58aa1f64ca8ce7d857176784778a48233114a8b87b36b3b4cb93ccc13" \
                               "5ac93060fe2ed7c94f79f347018cc15adc23317a2502b2064e5f9970a4296faf" \
                               "bbca7eb67b76c3705b7389af647f54f6c0f36901086d2551b1b450c5015b2563" \
                               "9aa6bf4122253d14794ae2735a0b1fd61b6a69f20e6d008a0aa6eca44a045c3e" \
                               "8d90f89156e316ccfb89d26dc9012461bb838f90e179e6e08ece20d97ee60a1c" \
                               "576fba5174322ea62f9088d3c10b1524a46c4c4df24ac386e74f1c415145ffd8" \
                               "e2150500cbafb7a0f79cf25765fd2c32e54481111b0ea5f625031788bcfcafa9" \
                               "e66454091341128c9de9f7304cce08ace4f1444cce7e750fe3dd85cc0f6dfa32" \
                               "55a66d08a118a09b25fde1e26d467d1e5f7c81511c4aee2e61f5c0bc263ec5ac" \
                               "0f9c4b1dc9941cb00c9e1a5fd53004439a1cf353e14fe4912f07e2822ae81ae6" \
                               "cd5d8b6504980ebb85be1913b62f075acff4b41abd8eb21257cf9a0a78b76265" \
                               "b6e5452d14fc1e54bf406140ba03168a397eb13748bd8e10e04bf57232591c61" \
                               "de113532eac8557f06076c57f3728754618442ea9b78fa0474f786e0ec6d4dc5" \
                               "68398d122111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                               "9da0ba072b95661816920f809e6dd85a25918405e531860ce3f905fe41cc0552" \
                               "1885294efdf77f0fe1cacc5920b52cb63013fdc852c4243b48ad55b026098ac9" \
                               "65f771b5e9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
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
                                        addrs_to=[self.bob.address],
                                        amounts=[100],
                                        fee=1,
                                        xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_create_negative_amount(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.address,
                                       addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       fee=1,
                                       xmss_pk=self.alice.pk)

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addr_from=self.alice.address,
                                       addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       fee=-1,
                                       xmss_pk=self.alice.pk)

    def test_to_json(self):
        tx = TransferTransaction.create(addr_from=self.alice.address,
                                        addrs_to=[self.bob.address],
                                        amounts=[100],
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
                         bin2hstr(tx.addr_from))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual('198b810c54523a7d3ba39b8e6689aa6057421be877528ff627cf43e59f6730dd', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        self.assertEqual(test_signature_Simple, bin2hstr(tx.signature))

        # Test that specific content was copied over.
        self.assertEqual('0103001d65d7e59aed5efbeae64246e0f3184d7c42411421eb385ba30f2c1c005a85ebc4419cfd',
                         bin2hstr(tx.addrs_to[0]))
        self.assertEqual(100, tx.total_amount)
        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        # If we change amount, fee, addr_from, addr_to, (maybe include xmss stuff) txhash should change.
        tx = TransferTransaction.create(addr_from=self.alice.address,
                                        addrs_to=[self.bob.address],
                                        amounts=[100],
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
                         bin2hstr(tx.addr_to))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual(11, tx.ots_key)

        self.assertEqual(test_signature_CoinBase, bin2hstr(tx.signature))

        self.assertEqual('92f50f236b2061e12e2bd05616d4334d3956cb1af5287f4bc0afc06280b695f5', bin2hstr(tx.txhash))
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
                         bin2hstr(tx.addr_from))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual(b'QRL', tx.symbol)
        self.assertEqual(b'Quantum Resistant Ledger', tx.name)
        self.assertEqual('010317463dcd581b679b4754f46c6425125489a2826894e3c42a590efb6806450ce6bf52716c',
                         bin2hstr(tx.owner))
        self.assertEqual('8acdf8a4d738516c024e26a0129fa49ccc3ff06d91d2443bebdb9f2caa7863c2', bin2hstr(tx.txhash))
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
                                             addrs_to=[self.bob.address],
                                             amounts=[200000],
                                             fee=1,
                                             xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_to_json(self):
        tx = TransferTokenTransaction.create(addr_from=self.alice.address,
                                             token_txhash=b'000000000000000',
                                             addrs_to=[self.bob.address],
                                             amounts=[200000],
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
                         bin2hstr(tx.addr_from))
        self.assertEqual('01030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada356'
                         '5854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e',
                         bin2hstr(tx.PK))
        self.assertEqual(b'000000000000000', tx.token_txhash)
        self.assertEqual(200000, tx.total_amount)
        self.assertEqual('0f32a0a656c87e91a0d5229a67f3ea66f56b284778665b6621bebe59ac98afb8', bin2hstr(tx.txhash))
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
                                             addrs_to=[self.bob.address],
                                             amounts=[200000],
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
