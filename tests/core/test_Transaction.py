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
                        "3c3f3f6cf7134148dd1c73bb30e17a0451217a9cca93807bb212efcf7810a524" \
                        "909ebcd17e3db32b97edba3a7de58f1673e09a0c83a059793d3b5df4ddf44cc3" \
                        "839473039659fe44cfe75c35d3ccba6b68bb2f1f9cbd194507bb52f60e89e62d" \
                        "cf104d0fa92fe004db5c69c9268a850acdf153f1e8aaedfc65e9b41214d393ac" \
                        "3e201fdc5e34a68e794728d2b388cc0ea10d5918bf7954b4876deb03693ec44a" \
                        "6f2fd2efe307bf24f3fb550eb0a3a2acd0907e30abcc07acf3fc7136c455cb61" \
                        "180a2d23f7326dcf2f564c92480ff19ec6699c3dce45f61791dd60cc5285506a" \
                        "67d408d807436a6ef7e39bce60a636eace75be0f7047aa28340d1debd49cf5cf" \
                        "c673f7256a6e2195ccca792bb6511b2c2b45888878d05a27ea129627da356c0d" \
                        "e849840a4977e502cffc30ebdf04cd5ac7038865e2c3c1262fb77e31f2fbd8c1" \
                        "eba24a76768bc16de9588ee4afc665cae752feba0b3aa407d686002acf320bc1" \
                        "0bb738e487dbe406d00edd7b1d84d4a9b039f30bd466b95a87430bcecdf79ebb" \
                        "da11b9adbda3c387957078d918098bd79eb68185e596bb63e930f6cac38a5055" \
                        "f755ff5738242a2d3b1f93153fd90ab349fd651ff27dc339602f324e4fdc98cb" \
                        "5dd4712976688612390460fd4832fdbcad01b0481229bcb44bd2cb62e01305fb" \
                        "0ff09930b7e9700d8057fbed7c5ecc2cfed68d77e51f8bb9ea5ab0d768c5d365" \
                        "0194ea64089bea773cd325b9215d3ae8fdb63eb120b54af4fe478344014593db" \
                        "400efaf05bdfe1218fa0c9104b14bc87d81bc98d3b86ff90e44cf8d3dab89f25" \
                        "853eb4862c4a070a10873e47477fd5dc35362de92cb72f9becf1e67a9130473f" \
                        "91ad4e127105bc9fe284eb7cdb41f5016a585deb2ba9b0fd41d21f32029a60bf" \
                        "40c322be30e079a06fc0f64d40934bb6c2f2b3398d37edd388e5386faff438ff" \
                        "e0c16283667df70eb9b82e99bf11abd06b07629becdb0f707f2f1d689d2679b5" \
                        "e50577747f7130500000458437368f013de9ec6bd7014ff18f0d5104f4d841ad" \
                        "c738d7c42977c1f43367acc0895af37a68753aee0a1f06548a2f46f448b92915" \
                        "5511821bd7b2249e9881fce33283cac44d3d6c41ef416f7b761a4487ef329a67" \
                        "0753e73773c5b9bec2a94d1a6491ec72698d0c70575a63a4a7135c10fdc25157" \
                        "f00722029f743ceb0ca1ba1dd44c0928bfef20f94b5b4fc6873574046c3a3696" \
                        "e01b4c81155bbc79f2e1bc3c2cdb5f63b76f6c295ab08cfad4ba4f1d83043bf5" \
                        "89ee6507b29b0ba4b7347aed5f192925c4cc14e9a2e977e07223c3845551adf9" \
                        "6fd9bf3a89ac4de38b57287dd47f9c4aa788570b29dfaf5f58fc0b0b915252a9" \
                        "d3e8350ba66848a4e26cd2fefd9a92b8a0679afba49e6fa71288b08b3f0c0867" \
                        "0871d205de86de79422c3807450c990ab080f07d76f46935475e3d4a8ba2aa72" \
                        "5865afc3577c09e4aadb6f0e2ee973c6192c6e5876c1d0fcbb1e54fd022302c2" \
                        "e5752cb5783cbfaa194d6fcc92b566a3ac41ec6c3fdbb26228ea014975fa584e" \
                        "55c57f5a3f92c5df896df6010091c6d6fdd30621c9ac62225e38abfe6757830b" \
                        "d2019a58f976b6d1fbbeff0c0e667151e72f4def3f70630e2c9bfa3f6011c954" \
                        "244fbe280dc66a5d2fb031b72ac9106158ff1d40d8b3649354d8a077db077533" \
                        "ad50fa2572781e487f13f1359eb22eb024430c00e51b1205630de20c591000c7" \
                        "6e7116206b118bf3471cb2082231e30f698dde4af3e07a2d33ae4973a42ac28e" \
                        "3c5646b223b0eae3539e266268e3fb12557329d2e9b6f6300b3ef01480e0eb9d" \
                        "a50ffb90c8de5fdd98cb05862a863fe9f62a5ccfa7b1634e20c0434d3cd769f8" \
                        "ceb7d0b60bd64b91af890e3f397a136fdf5fefefa183483b2b7661ae137da071" \
                        "0f5617b9d6610809d1382ee89dfbab62cc5c42a6de5dbadf37f5cb7ff342fb82" \
                        "6f81372cbade4c5ec73548208671187f7b564c514ad0364ff8c074e10ff9a97a" \
                        "db4a8e2f707f4908432a722daa116faa11f74d076d022df1fee44e1e40e330c7" \
                        "b1f45f0955eb2167664d7e29d8a65647bde1cb81ec5f754eab732a6bc7942281" \
                        "83aee9e94bbb2dc83721142a89d162e65e9a875fd71422911c9da9fd61fdf61d" \
                        "0ac6dfbb41b8ab2a26b9787ac9f38e6696968b80dada5d63e71e58d4a8a1333d" \
                        "471b91d35f4393bef9bba590336119b9f7d87f546758deb4e5480b882e81de6a" \
                        "dd37945c9ddba84472515f380f468a9dab4bce3cc562f9262309f9af9b0c532d" \
                        "a64f0bd1c89e4923e42201e5180e6829c75c64aad26d3be19727665e019b15d4" \
                        "5c03cc41846ca40249e396ad31b467eef233c0556dd0edf50ff06e2d9bdf622e" \
                        "0a69b4da84e241bcca9fb170572f2ab032c52e772120893e20fd2e550d577104" \
                        "ffcd3b74876c9e1893b094dccdf4dded0df453dce7977f11248fb5b9cc5d5f19" \
                        "afadef3283c1f3b7dc392c0887df8bb403dc382b64e17834005885fa4fb39250" \
                        "4a1e7a73eae39daad61bf7381674245000a65e48432b62c658a5f01432ea0564" \
                        "0462417ae89f765ba2c0ae9b4a9d31800fbd72e80adcfc88bd4ccd7e58990ae5" \
                        "ecd17123614b435be6105e1c8d4a5909f30ee94ef3051d42eab9799c80e34ebb" \
                        "e8f782f8cb7f9eb802aca4c1578fce45823117e5f9ea4139592d8e608e59335d" \
                        "076a4a3835165efe7f3d7c1ccd38039fb49aa8917610a02a22b0e01e6277d483" \
                        "dc9a3bd39edfab15df2ada7d622cbbdef9da5a297250448341e33862677b63dd" \
                        "90643bc70278f83a65ba5fcb407afc83da95ea3a4dd801e5798554bb6cd57b34" \
                        "92e1d269b77c5c6109f099685533419fc2a788c476ef4bd7773145b8e8128fbe" \
                        "f3a95dfbbfe3cde1d2dbb16eaa47a28e0b4b1ed9de45237f79c50de0b6d1ed0a" \
                        "981b86382111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                        "9da0ba075e59a7d9db3b89a7f348ceddc3ba47e6097e56a51d8672902b1bd7f8" \
                        "bf9487711e6b056b88bdbfbc3e9ffd26832097418c866108ea2cb38def9968ff" \
                        "29e42efae9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
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
                       "15af977faf540326292558f3ddadd208907f575fa783a1f25d9e05de2c0678ea" \
                       "5aba805b7c028e5c975acd2471b5f5837b90ffcd10852d885ed570f351c89477" \
                       "b759b9febe066b202ba0fd2943a28aaf2431649e206071f9073e2f65719e462e" \
                       "bb7e2df486575887fd7ab5f7e7b41f5752b10d3fae2fbc631b6d6abe11355d4e" \
                       "291843e8b028338598f6e2b88aa4411a4a86cf110473ce5319a7ade1b86ef223" \
                       "aee39a1bf7326dcf2f564c92480ff19ec6699c3dce45f61791dd60cc5285506a" \
                       "67d408d895fb959fc7c9e69aa7daf21ae5804d22c6aa6019000275bb6c1e382d" \
                       "634565c14e429745b9f0f5942caaf9d06f9f6d0aa8cf196d970ee12d1e5427c6" \
                       "e2e1f4d52146c5f7e49a998363da5e6914cf6304d27ad3fea113385c81983be3" \
                       "736258b8b38d2dc81ee93e03e285507122239fd0801f878ab10cb87ed07f5f48" \
                       "f628c32949ad50c86c4f8e13fce33b9ed75fce18bd3db318f8f92a86a831013c" \
                       "797fb1bfd65ca991c694715d4c794d9d297f955a698ccd9e9996ddc0f432dea5" \
                       "df4fd6b6e1868fcc1003d13e768d66ce3bbec029e52d56e3c792c3928ef08e23" \
                       "11f658afdc3b8ff9d31f0828b31163402b885ca57a90be3f77ff90a1efa68ef5" \
                       "b65f7afe088b7bf2c955589c0359089817a44965a06b7327004c896c2a93efe6" \
                       "a530e58c089bea773cd325b9215d3ae8fdb63eb120b54af4fe478344014593db" \
                       "400efaf00e56cc0403a6dc3c8cc2f905a7b5fbe0eb035e2b9e76530b78c487af" \
                       "b8919dc3d78aa03ff22e49a558306f45f2b220e9c59b1cf04ebaf50da9962882" \
                       "db701804ed1762dee373d25ee43cb5de67dc017e4a311d2bc242f8cb1361f644" \
                       "d2095903960c799275dcf7d6214442c00be2b7677102f61a2ccce33942a1eb47" \
                       "2b8c0d5c667df70eb9b82e99bf11abd06b07629becdb0f707f2f1d689d2679b5" \
                       "e505777489dfb0a1e9dcde2fe6fe5496f9e4217720c46423e79a531a997bb75c" \
                       "f2730d4aa09cff8338a101bdd4bf638a589ecc5b4dd0332740269e338f8349f9" \
                       "881d9e578e466f992bc64befe9ed339c23676dfa4e1b6087cacc37498d8f3855" \
                       "f74d0305fa790d128ca99a2aadb65b8ac55b8149bbb22b64070c0c3b9450820b" \
                       "87cc86df9f743ceb0ca1ba1dd44c0928bfef20f94b5b4fc6873574046c3a3696" \
                       "e01b4c81af31f246b0ad300691f507b37f297c3afb7fd2217848c421044eabb6" \
                       "5b18f70ab57def74ca9397c3bb2811df5214dd56b16ddedefe2fe9f4e183c561" \
                       "7c529af0d2bea614d0fbc2901e725fc9ce126b778d83340777bd626dc6a6b4c9" \
                       "b95b1e786e031768f003cf4911436144a8558140b7a3d2f920feb45a290a9d4a" \
                       "ea345571364545a5f615044e4b229d6017b8fcd31f2155110178ce96e6dd98ad" \
                       "97ba45be3769ea1ff35f1e6f1e3ca7cefe67b9c6bf4edfd301271a71e619fa9d" \
                       "2b7a3255bf055788c0e851cad41507b06f873e3eaa01cc53e714af90aba79395" \
                       "9b3e21dbefb1a407da402f377584fae311bfd1719bcbfb8b1ba340a5ad9dbc2f" \
                       "fb0ebb1a0e629f6ca1a5c5c5af6d35cfba74527df0d0631b9d0770e20ca73679" \
                       "406e0f0f3191863db5d84463eaa7dd8a0b6835209ba500093bc66a80ab22a0fc" \
                       "09d22f6576bd6e15cdc2a99e303967365386f60735814ae27c5456c8a4c8e2ce" \
                       "793538170cb1a3089db078207ab7a975bd4cbd459fcafad253add213757be996" \
                       "64660c7db6ef04072587b28782441641be578cc97ef4a4f04bbb8b96674a7384" \
                       "1e1e70e67c95842d6bc1664041847fad326eac879b42d08a5402663bcdee434a" \
                       "e5640d9403f22bdee253c01d47a142dbdede1ed53139d8da20929751e5f574b5" \
                       "77b377062dc1b66fcc1caba75f413d6c087477df6f527c7a9b8c7f2b143d2cbb" \
                       "684b1abe516e586513e1d38e5a84484a45cda9ff5413a3e0fd4fb4087e12f6de" \
                       "752275d7767a9b5d81f2a16ed8ac51d2beedd31145d5d5cb5cc311e2de45eee6" \
                       "6f4fde3da37d6ee5b6afdf22727bfc9d791259f735d2d71b124269152945c226" \
                       "1c9f92eedf82deb74554a65fe021d1b8996aca9ba97be8e6050a4302a7872686" \
                       "1942a66347929ef65a1424b5fb07d094a8a98a09db01db22bc6c5cf1e51d9075" \
                       "0bc8224594322068041ce769f59760ffd593a2c97d04cd1fdefcbba79b7a7fac" \
                       "eaf15952e4cba0f38a138a148ef12133ca534e161bfd812b61baec9f012b6fc4" \
                       "a44b60a572e0efcf15d0f3ccbb51530d649c48b9c65279573b127a6780c25b2e" \
                       "2c2cb22ea37361ba1683de2569d922ffcc0a0aa09710647c23ea2adf156a668e" \
                       "d24e39331bf901805b07927b3bce154f12170775b7c02526868b4f6fd6bef6b2" \
                       "cdc70bf90b5184034babd55fafae7f4d1d52ff7e6cc036c48da9aeb92210ae7e" \
                       "0b31be4183c1f3b7dc392c0887df8bb403dc382b64e17834005885fa4fb39250" \
                       "4a1e7a73129c3035e43e1a0c019fe04c465a535f7ac07ff07937a275b4d17ece" \
                       "8e76ced02c72b0f7d154057d648594ef8590b508629732ad5a7c41a0a157ba9f" \
                       "940518bb8a891a69ca2066769712536c7de9d6b2668c58b9c21a12b9d54aeb7d" \
                       "945746431341128c9de9f7304cce08ace4f1444cce7e750fe3dd85cc0f6dfa32" \
                       "55a66d083807b3459b4b4130b261eaac342b298d884a1696d5253535d96923ee" \
                       "00359ef583aeabfc938e84a1ad4d8adbba6cef1d9e0d249fb56dfc765b4623ed" \
                       "df009e51924671963291af73c1f043164404a965f32f82d6bd402a753b9d663f" \
                       "4f3e15df540a466bcc7834b2ec0d833aa11e9e7a529df81ed4b1f88bfd8c2920" \
                       "924359493a7ad481d7bd1a4906449cbe51ee8e56f2e06eefd063f9cfccd3f6f4" \
                       "a99b5c6c2111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                       "9da0ba075e59a7d9db3b89a7f348ceddc3ba47e6097e56a51d8672902b1bd7f8" \
                       "bf948771c68be98cc1c55826e0cdd24cfe56227d071e7aa802ecd9fb656da970" \
                       "a65bae77e9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                       "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                       "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                       "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                       "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                       "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                       "98675eed"

test_signature_TransferToken = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                               "3c3f3f6cd87250b2ad225ced6b8c902a5fa1ecfacaa6744f6f42323ee586d873" \
                               "f066388ab9f17ad396aed963678edeab3e6e35c082ecd7bb8ef568f2da92fb2a" \
                               "7336a7d523f916073913b9f3095c0ed7f300d833ad0ccdcc3f2469e228b83466" \
                               "b86dd76055571dc4bd2201c87488c1c68162ebf51b59576a4c0cfdf034f2ab32" \
                               "9dc15734cf8d25676d88db8b0b5d36444ea409ac74197870883527ab3c3693ba" \
                               "a6d1e82b61e46a5b6b2614d8e1520fe4fe2a48f825c7c43dc65634c4a8f808f8" \
                               "71c88aa609136a8f97c8b21014d994ec7d901f14440dd4dd1ad65605004f0898" \
                               "6253b8c41140c7ee3878e851f470607cb2ce124708a27acd4f4f01611adbff19" \
                               "6747a2584f284a0f4ded53c4569022e384ed11a2834ac8d4a4fc892145230847" \
                               "57d5b84f810697a42357cfdda8b3c48e1f8c8e2ebb65583dd140e3624f1227f0" \
                               "ce80f8c95b2b30d4466a3ee14a68704b8b4768c7373a507e9e68e2262289b1e6" \
                               "df15576a04198d1956137f1c76408e2c9c71a8141a5ce2f10a836b5187e92d33" \
                               "615af8e4bf2602ed787adb36bc43863135797bf8c5f25dfcb795a079fb6ca831" \
                               "904f4d8ce1868fcc1003d13e768d66ce3bbec029e52d56e3c792c3928ef08e23" \
                               "11f658affc1c259e0159c5feace62861a0227d2e6870e092ea39f3b3f76bbed7" \
                               "c0f5ad5021ce135ddf65c39f07a598f6d6aefb75ab511b18b2984d5afcb03ae9" \
                               "138bb0b4e4812fab04f928a771770d14a944f221abc5ce9f4a3c8366b26d8a8d" \
                               "0556d1c04b5262a9cc92f8d8cb24c4cd631ae57942f0b78ef5d99a1f99e902ec" \
                               "f25c2bdea4b5c683ec03ef0cf0ee85c8bcc87febb42b0b69eb18b9df46369627" \
                               "e75d1f3cdf9a22eb592e26ff9c70b5a8cea17b3edbbc934bf0afdd8188e7c006" \
                               "ba6e874c536ddee69002120459d8bc237d9dac2059bdf2d591997c3e4c385d78" \
                               "941a566cc2552eaa461c93911102075ce3e10e1c4bad91b2bfb961e31ab8138a" \
                               "863f0e421e7cd30a1dff97489371dedc479310f5ab44b160774ceae0b93bdeb6" \
                               "9665c32c640dd91071610fc57cecb0b00219f092ba27b27e5bfb6bdcb6815be4" \
                               "013bc5575a10a9c8651c08ffb0830b175e6200fcd812cabdefc0ea39d82bbd79" \
                               "82d43e4bb2f461c972ab0220e4946c3b6abf5f8784fe77eff0de8b8df5a595f3" \
                               "d6416e653e1a9028d2732b0058616706d79cb9169044072922c8cbad8cc56b5b" \
                               "2a14dfd64bfbe7705b035f0f8ba824a097c9bcbe00eff81461e71a1cfd868553" \
                               "77efa04ff69f7101567af0bb381c033efef8a9137ae70fb3c05616cfc7bdf517" \
                               "701cac31ee9015c59fb8419cd29fc03e2a7274444229c6f69439278e941569d9" \
                               "f21a6e8e6c9015dcf201bf91451d0d69fee85a28d53d9e422ef4cb4e70fdcca0" \
                               "fc7a7b398e73d4b0c4ea88925ddd112ffaab5a15b63bb1e2806a40c34ff41f60" \
                               "56595e552e4eb3dacca131d70f84f8d376717a8eed293ebe89d3d5b6eb5cac37" \
                               "bb23a20271c6357625171ea8eb5589edb1b2b3991445ba6419ada8bb46080245" \
                               "e5deb9657f6ed8cdc5cbecd249dcc7ff36da100f9175d26a01b6fec2422fb37c" \
                               "a1392cbd5e7a93b2430cbf30fc3a51019aab82e73a4bb6c7ab32740daaaacf20" \
                               "bfdd093f5fe033f11a3d57879e8d93291a035470e2e83cff0af30ebd66fd5944" \
                               "eedd17c720be1caa836ab53303b8571da0b73405e18d4f16335dbd60453fbac3" \
                               "6868a1b4d51930ddd4a884c2913b4d9e6f70b61e0b94172b77051b04828c66ec" \
                               "60d8abcd31e19d10e881da3fb6a3b096a950d5e12c81a32670def7f0447671e7" \
                               "2bd11beea1d3ff0ab6406f5e33ea5b4f8e2d40f20e0c3805249f4eb0029e7294" \
                               "8fb471aa2990b89a6d0b895124860f841a3b1071b0979b938f78d7b82747aee5" \
                               "338e40b92dc1b66fcc1caba75f413d6c087477df6f527c7a9b8c7f2b143d2cbb" \
                               "684b1abe2b5707779d1f0a6dc9ae73e46655467867d033efdc324dad08cb89cb" \
                               "8a4d438288170fd144ab595fef9f61aac6445286b3efa86145454a12533ef4ad" \
                               "9a836e442a5e08f05600baf85aa11ab7809e8a243c5b99e392a019bb761eed32" \
                               "144c0ae4158c8d63275bd4d7c395fd50bc6f80779165fafdd4636537d061b316" \
                               "55d7f14e76b1b3c074eac387af02bcb67b7c764ae400ec164e91c5143a8f03aa" \
                               "4985a0e4f742a65757bb6d73dd029774cdb216dcf6788d4823265fd4f1ab879e" \
                               "196e29c577419c8b450ee0356d65cbe05a92fed183170b9a8348e8d60a18107e" \
                               "e6de90964b54e576b345e9301f4928ddf1eca2dabaa2149a92d4a0717e35dd2e" \
                               "d90f63e868041d516c52f49c972dd4afd9353fdd2588750a82a388e956ac28c1" \
                               "5750b5d0409414352f3b0005c204cb4c1c3406a5f1cc823a51bd7820b9a5e0b8" \
                               "6d5928927f4583b29c2e1abfd2ceae36512b8e0826ad5b60a6013a9dc7a259c0" \
                               "a4490521c07922d4cf4b3a04acfb552c502f17efc652606009fcc255ed89af79" \
                               "d3545f1f53398d2490e2b2cb1c4fa49aaebf103dc87d5ca716f8d14f7e1a0b78" \
                               "a8f8a460d9c8ca20146963f804a78c50ed0f7b3d207046c56bb8e8b881b6a203" \
                               "87d85dee644290afed7fced6ab82495975cf5166688bfe33d489d51d11a320ef" \
                               "db30f30fbcc43ef93907ee5e445dbecb5e400af59fd250ae66435fa8f742c985" \
                               "186afa53e5ce9245590022441f7bfa9ee1b9e52a231ebe2ae08d931ba869d64d" \
                               "b2e77e4e5b00aaf7d0ff707587a5eaf6e547d95b0d263557431ed94b0bcfda9a" \
                               "c2b2f9865a1047fe6e2b04191ca8957621392ba27c970334ad339b31e2607022" \
                               "232c17a3638eecc58c2c9ea2cefbd80d883e278414bb85e8a46b9cf793d4ea26" \
                               "2609f1484a5751194a281a2b1ea7ff51204c7713b4d7bf31e5dd034780305f66" \
                               "87bf32ad2111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                               "9da0ba079a934ab085b2fd6dd340ec31e77a1aff6cc586730264da3232b3aa5f" \
                               "2bd2a254c68be98cc1c55826e0cdd24cfe56227d071e7aa802ecd9fb656da970" \
                               "a65bae77e9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
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
        tx = TransferTransaction.create(addrs_to=[self.bob.address],
                                        amounts=[100],
                                        fee=1,
                                        xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_create_negative_amount(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       fee=1,
                                       xmss_pk=self.alice.pk)

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TransferTransaction.create(addrs_to=[self.bob.address],
                                       amounts=[-100],
                                       fee=-1,
                                       xmss_pk=self.alice.pk)

    def test_to_json(self):
        tx = TransferTransaction.create(addrs_to=[self.bob.address],
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
        self.assertEqual('536c35bb536d324bd6abd8ebe951b010157b95b8c72ece24d562939930f70a4e', bin2hstr(tx.txhash))
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
        self.assertEqual('0103001d65d7e59aed5efbeae64246e0f3184d7c42411421eb385ba30f2c1c005a85ebc4419cfd',
                         bin2hstr(tx.addrs_to[0]))
        self.assertEqual(100, tx.total_amount)
        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        # If we change amount, fee, addr_from, addr_to, (maybe include xmss stuff) txhash should change.
        tx = TransferTransaction.create(addrs_to=[self.bob.address],
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
        tx = TokenTransaction.create(symbol=b'QRL',
                                     name=b'Quantum Resistant Ledger',
                                     owner=b'\x01\x03\x17F=\xcdX\x1bg\x9bGT\xf4ld%\x12T\x89\xa2\x82h\x94\xe3\xc4*Y\x0e\xfbh\x06E\x0c\xe6\xbfRql',
                                     decimals=4,
                                     initial_balances=initial_balances,
                                     fee=1,
                                     xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_create_negative_fee(self):
        with self.assertRaises(ValueError):
            TokenTransaction.create(symbol=b'QRL',
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
        tx = TokenTransaction.create(symbol=b'QRL',
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
        self.assertEqual('b887d83f2cb517bc6c4837cab7becb4267d054dee3242a51ce41eac7314697a4', bin2hstr(tx.txhash))
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
        tx = TokenTransaction.create(symbol=b'QRL',
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
        tx = TransferTokenTransaction.create(token_txhash=b'000000000000000',
                                             addrs_to=[self.bob.address],
                                             amounts=[200000],
                                             fee=1,
                                             xmss_pk=self.alice.pk)
        self.assertTrue(tx)

    def test_to_json(self):
        tx = TransferTokenTransaction.create(token_txhash=b'000000000000000',
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
        self.assertEqual('2a862e2715683ede4f177f928b558fdb6c1a1bac5c17a34faa57b5ca2c0a9f3f', bin2hstr(tx.txhash))
        self.assertEqual(10, tx.ots_key)

        self.assertEqual(test_signature_TransferToken, bin2hstr(tx.signature))

        self.assertEqual(1, tx.fee)

    def test_validate_tx(self):
        tx = TransferTokenTransaction.create(token_txhash=b'000000000000000',
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
