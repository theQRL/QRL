test_json_Simple = """{
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
  "coinbase": {
    "addrTo": "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
    "amount": "90"
  },
  "masterAddr": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "nonce": "2",
  "transactionHash": "IiRgzFerhoO0bxgx/mzxgyx+MTS6900zv6+RdB4Zy6I="
}"""
test_json_Token = """{
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
  "fee": "1",
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg==",
  "transferToken": {
    "tokenTxhash": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    "addrsTo": [
      "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9"
    ],
    "amounts": [
      "200000"
    ]
  }
}"""
test_json_MessageTransaction = """{
  "fee": "1",
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg==",
  "message": {
    "messageHash": "VGVzdCBNZXNzYWdl"
  }
}"""
test_json_MultiSigCreate = """{
  "multiSigCreate": {
    "signatories": [
      "AQMAodonTmjIiwzPRI4LGRb6eJsB6y7U6a1WXOJkyTkHgqnGGsAv",
      "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9",
      "AQIAZwJGsAJkNrcX8Znj7FMgumq2HV7d/4EawZmp6bhx0ygBeLND"
    ],
    "threshold": 30,
    "weights": [
      20,
      30,
      10
    ]
  },
  "publicKey": "AQIAsGVJRyiiO8joHbY4VZG1roHa31u5nxY+ITxV1jMdC38Q3DZ80OopZx3kIiEaiH+z0Zmwp/GzwC+qYq3DTTpdqw=="
}"""
test_json_MultiSigSpend = """{
  "multiSigSpend": {
    "addrsTo": [
      "AQMAHWXX5ZrtXvvq5kJG4PMYTXxCQRQh6zhbow8sHABahevEQZz9"
    ],
    "amounts": [
      "100"
    ],
    "expiryBlockNumber": "15000",
    "multiSigAddress": "EQAAOQFwwkX2TVVwVgQi6XffhVe7j7F0BmGgPdcBXaOaTQOGQq0C"
  },
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg=="
}"""
test_json_MultiSigVote = """{
  "multiSigVote": {
    "sharedKey": "+J13jHTkcybczOMHDHqDjo97JhvUYsRx+adev5c/a4E="
  },
  "publicKey": "AQMAOOpjdQafgnLMGmYBs8dsIVGUVWA9NwA2uXx3mto1ZYVOOYO9VkKYxJri5/puKNS5VNjNWTmPEiWwjWFEhUruDg=="
}"""

test_signature_Simple = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                        "3c3f3f6cd87250b2ad225ced6b8c902a5fa1ecfacaa6744f6f42323ee586d873" \
                        "f066388ab9f17ad396aed963678edeab3e6e35c082ecd7bb8ef568f2da92fb2a" \
                        "7336a7d58fe826663094cba678fe71cd3221bff405f9110acfa4ea58b6a908d4" \
                        "e3bcb5e555571dc4bd2201c87488c1c68162ebf51b59576a4c0cfdf034f2ab32" \
                        "9dc157345e34a68e794728d2b388cc0ea10d5918bf7954b4876deb03693ec44a" \
                        "6f2fd2ef34d07dc3cc49dfaec2612d9ae94881e3bbba86991e935d2b585be306" \
                        "7f9b91b5d20dce21742ce4cc0b20eb575c86b428a9f2a9ed1905d67250a8b0ba" \
                        "6b2c70ddc2b832c21ffdf526bfcba0596e4a9dd36dc95d42c27dc235cd482464" \
                        "ef27c8616a6e2195ccca792bb6511b2c2b45888878d05a27ea129627da356c0d" \
                        "e849840a2c40dabca5bdd462bc16f6b85a163b8727cf4a806814770fed8f91cc" \
                        "7106097585df2ff582aaa58cac02d7a6b8c13c655619f04bd95e7819e9353f9f" \
                        "c727e023ef1b89b72c3ea2c6c89edf4917071690984a1b4644ec523975fe2cbf" \
                        "113246184d6f5a5b0fc6e925605ef930009415ccb292db9983ecfcaca62601c1" \
                        "860418dcb73ca1958f83febb53cccd3b1b3767ac9d18a9446817ffbfccc7ebc7" \
                        "dd33e1876475e5d9d325092d1572b9211df2a1547ea08d49c2d3b6441bb89c38" \
                        "db466135b4c2ebe50885861560ce20bebb96ccbb166ddfeaad1507089eb385a6" \
                        "c40d7f94e04eb00d916ecb8fdc14908feb3db6f026e13d5bf7c60ff887ad5ccc" \
                        "9cd295327da6a2c091f82a98cb7ab34c2e49541714ee9f55b3963d7ee8f1f870" \
                        "73fbc5c75e1f86e78b149ac7fe764b326e18404203863641ba9fad2b1a038c7e" \
                        "c1abb0b3ec07183e749b4a57f8eacac0ee2192a9474f63adb35c91abb449fe50" \
                        "de1858342d3c9f0eac99611115c52e002470e43f95a1fa7b666263eebdc3433e" \
                        "68be9534c2552eaa461c93911102075ce3e10e1c4bad91b2bfb961e31ab8138a" \
                        "863f0e429a10fef69e6d318f8bd6cc7523b905c1e3ec097d668fbf478b30cb3d" \
                        "2cae1ba4ff33b481e05c9049756621e7627cc8860153fe641691993b28f5232b" \
                        "b150a5f9b0dd0af07834f9dcdf4aa77fc689fedb190164b356aeabcc3e531f66" \
                        "d30481369a93b10e1fdd4d426f23602184ca8fea5be3353e2d0902cc48df1246" \
                        "4d432e7dacc3e3556bf4aa2969caa0e7888ed3cef8410421ebef187a99361caf" \
                        "eda041df53fe1a494534e4c9117c48b3916843dc5252b5bdb56bb5d9effe5819" \
                        "d22174e5c62e47c124e5bd10102d9894e605827e5914d3c10818162ac5fa4030" \
                        "b0dbc56d08ada3884320309601580f85f94b7a1d180e33f0ede9a7d1b3a46259" \
                        "8de014c6953de1640f706c060e3b92e259e829752e42e70dea78e04e1ac9c5a8" \
                        "74a77d1d3cc7760c92aea2a133509efd579e8c9ad994c02e7a1411031698702c" \
                        "247726141291ec7ba50d58f70cdaaf9c4a9ca6590778139c8c66465e2d032f61" \
                        "55946f7e03433add23065e774c3887743cdb8b38807c292436a973d6aa235d0c" \
                        "ff3a872dd3c864ddb869a2a247a13a4e7e9792e25371d3af6957e8ce9806b27b" \
                        "cc92369a4b6bcd4b84eafcae09ad1278a349321c8084ce24c9d389540e6893aa" \
                        "09347b00fdf56441b82074295c2cb0fe0b7afc3bd58f217eb0aee5d6fc265ba8" \
                        "c459cc9588473307c743c3803fb5103544c3bcec638aa0e608211d6155d401d3" \
                        "ee3c2f836b118bf3471cb2082231e30f698dde4af3e07a2d33ae4973a42ac28e" \
                        "3c5646b2844835358269548156509c6efa6c0604f1852cae15495597f270df31" \
                        "4d73171ff7b308bcac078464754c6d18f27032ea85e407b45fe83354067c5bda" \
                        "2f82dc9854e90a07a11844836a0b67a80d2375c4f6289e724a5cf8da34a3248d" \
                        "1d00eaa3ae0f2389a80b51ba813fcaa638a8eece14a85ee64ff8d735e7a1188f" \
                        "ccf5dcedd17acbb8d46d149087cb1334780e37a0a43b604e1c45356ac3067e13" \
                        "b8ec1eefe24d775848e5a891a6f23ff84dd70bb81585c00ae7d390a0d80fde58" \
                        "fc1bfb47c12e749506846ad7d6cd0f4bcc35d49ae7e89c80d4594eb66d8a0db6" \
                        "de4ff4c0df82deb74554a65fe021d1b8996aca9ba97be8e6050a4302a7872686" \
                        "1942a663363893d5367ffdbd85ee86ade84ab492682e3a6bd67e27b534a0356b" \
                        "53db39e13c3a825296e2330246d27b3b66cf6db99c87403d372b1f2e9ece2d49" \
                        "cad96146b43ddefa92f6187c63804f9da5d1266caa5eb0c5dbf4cf627adab1fa" \
                        "2a47f0acc89e4923e42201e5180e6829c75c64aad26d3be19727665e019b15d4" \
                        "5c03cc418aa1f64ca8ce7d857176784778a48233114a8b87b36b3b4cb93ccc13" \
                        "5ac93060d0309a9fe346ec7db8dc525d9d2a67b1454ed6f3b388d4163b4d13e5" \
                        "02b95e7c69cf1b6b382d0bb58fad46463165a723cd5b65d4e70058fd1c9c6363" \
                        "ffa5d170e2c0f22b823a5156eef56553761092b4d581c13e1e47c46d69ed4b91" \
                        "3af1e271f68cfcd43d8c0681590b2abac50ed3bc33fb67f5b71daab8886ca2c6" \
                        "9e073a5edd821ccc615f45603202c40bad1e338fbf45b1c92d4d04f4e45c28f5" \
                        "3188a807cd62e6d38098a56f2d4c72b1a681a08f17178b447a880dd883ce49d1" \
                        "8f36bb7e1341128c9de9f7304cce08ace4f1444cce7e750fe3dd85cc0f6dfa32" \
                        "55a66d083807b3459b4b4130b261eaac342b298d884a1696d5253535d96923ee" \
                        "00359ef5c9941cb00c9e1a5fd53004439a1cf353e14fe4912f07e2822ae81ae6" \
                        "cd5d8b65b875033859025d4d3c9265614b085daae72b160f471c77f6af443ac9" \
                        "61175698b77c5c6109f099685533419fc2a788c476ef4bd7773145b8e8128fbe" \
                        "f3a95dfb9879157f1c9722c2d00b28452c606037156bcaf68cbbc8f6d4fd371a" \
                        "1acc0ed96f7e524fc9e31d5400049be470af36b375943d6fd33d4edd6fc64514" \
                        "1d3b735cadfb36679a959451e66714b041e9879566d50d8f13e5a4eb519b53b2" \
                        "9e0cc58aa36f19e4bf59a90736d83d4c371d29ae6601201e3329f71922802e6c" \
                        "f728113de9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                        "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                        "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                        "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                        "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                        "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                        "98675eed"
test_signature_Token = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                       "3c3f3f6cc186a29f9a39b38d7dd73a51f5dcdc759f9349e9a33ec47aa9e1171e" \
                       "fa0426b30d5074b25cdf27cf21938f1a6a208ec739f47c982613218b48c5b02b" \
                       "fd4052a923f916073913b9f3095c0ed7f300d833ad0ccdcc3f2469e228b83466" \
                       "b86dd76067016d5c5c3552b3314bacd53ab5442129540ebf6047fab4e3f2ea68" \
                       "dd6ed7935e34a68e794728d2b388cc0ea10d5918bf7954b4876deb03693ec44a" \
                       "6f2fd2efe307bf24f3fb550eb0a3a2acd0907e30abcc07acf3fc7136c455cb61" \
                       "180a2d232d1c1eac26d137e6b395b3deec26b1e66b543cbcb261eab981f5ac7b" \
                       "e9d210faff17cb324ad2d29718ae21688dd307487697acd422726d457e588f0d" \
                       "2ec15b3b68cfdcaee7fb24f0fd02c92e2df365cc9d89a87fae0f0768d3f11739" \
                       "693593dee7de346a1ddce5bb2102deb2bd1fb12a93c619bb1418544217f0f71c" \
                       "cb65890585df2ff582aaa58cac02d7a6b8c13c655619f04bd95e7819e9353f9f" \
                       "c727e023d231815e32918814ec344a7a2b65e1fbf85ab53f80ca4024c6b77ede" \
                       "4636b3bb666c03d96b2fd8e938fd1a46189d0a8ac5054cdde594a18fc4c2cf1c" \
                       "fc7f43308178b254d9b431a9c0cfd7a78b1dad393c0ccdd3dc5ecc9b24912226" \
                       "2b3f008c76688612390460fd4832fdbcad01b0481229bcb44bd2cb62e01305fb" \
                       "0ff09930e88dcd6a5d0a4ac5d968a79c838acd7769dd0bbc21a24695c05954da" \
                       "f2b049c5973866bd41ffc6a9b7fb3aff011b9b64df7dc361740623bce15f0336" \
                       "09a2a21ce0dbc9a8b8d80f690d200a46b433dc775df902647fdac9e9621595f1" \
                       "b0c86f06717bacc9f72c8f17701fe131cccf4f1dfe67129bf3880fa51f471fbf" \
                       "2e1197faec07183e749b4a57f8eacac0ee2192a9474f63adb35c91abb449fe50" \
                       "de185834e26d227bd00c966da00d13f8f195c13fa6ef2e9cd0e930811d0f2315" \
                       "8bd91243a5e66a0f5736e11dd2c9f5454348c88a43c2bebbf6c24daa230e7b4e" \
                       "6db3c0257d12dd2ab248887b4c1973e7431921b2f61abf16ed22a4b2e0189ce6" \
                       "fe304c3186be408a2a881ded2e8a3534ae03b07927083b8087891d54c12c54c4" \
                       "b4cc9dbddace3305df0a154c9536bb2a67a2513ba99e10cbda1cc2e3e3f0fd81" \
                       "e3660edfb2f461c972ab0220e4946c3b6abf5f8784fe77eff0de8b8df5a595f3" \
                       "d6416e652c2249e9b68f4021fedc23192c5161ec112f4e03abba776e20efdbde" \
                       "e8a582c8cd04b01bcb24ef635cb8e6cbb1538c5940e6840abe606549117095b6" \
                       "e5a504cdb29b0ba4b7347aed5f192925c4cc14e9a2e977e07223c3845551adf9" \
                       "6fd9bf3ab3659366f67eada28522fbd23f2e46a7d31124f1c31ec8586000c7fa" \
                       "5449d46b0f09d7aefc685866ad53dc58a2aa4388c7e6b1963556e682b869e731" \
                       "7b01ca320a23c75e301a4df09ecacc0c892cc1e43780f96a256d0639dcc374b5" \
                       "a13725dece716e5383077fcdd8db6c679e0d56b8efcd296894be8551d0b6eda9" \
                       "14e565bd17c88cb3bfa47d014d278dc95672e1f8e1764d3587aad7b37a2cc4d9" \
                       "634d2bc44415502bdef02de04d3c1c8ab4ec95a507c1932117971f81f081567f" \
                       "50349bfcd5b57bbfccc1867f9593657147ef23423db76fbfb53bc7a9e4833615" \
                       "c58f30984004f76d259d75d4a15a151942cc41f92cf8d2d8b14c3f538aad3e72" \
                       "5993a9009d72c4e561591279bf5373aa44ae6b71aee6dc0c29c2604af7f09758" \
                       "ff7616a3d1f9dcb486e132c1f7818acc9c6f4ebfe60ebad5ca63d86cecdc139f" \
                       "b2fc665be289caf43af02c034ed6a10a2469e2a40785d9bcee81cc714e70f264" \
                       "36f2883ef7b308bcac078464754c6d18f27032ea85e407b45fe83354067c5bda" \
                       "2f82dc986cfaf471dd726a1be1c104b61f543ae5814d19a37ae336aed7c2ae46" \
                       "1a669f3181d8179419f7540f59acb338834bb36d5bed4c718145e8bae74680d7" \
                       "37027f1a8fc35a50ab7821fee7b84b09cc1e640b7c3606f73c71b413b464e23c" \
                       "df81bbc9875d8ed5ae25bac46962b0476fddd3366de52efbc5887325ab8a9bb0" \
                       "c7d745eabdc6941bea89c40be63a8aa2db07c30a9492145cec0fe005fa222c88" \
                       "84161a1041021639106d925c47308fd9e98e9909396dd1086ab8e1df8b2a5db9" \
                       "eaf96cb989f52e1593e0405688a4e2d6a803a2ba03dc3b13ec0e3f21f219a8ad" \
                       "1cbaf53d3f23e98bd4afe0fd91e62063930ce481f955d33df163f048b8e3f551" \
                       "91af094302406e4c6eed081186753cfd6274876748dac65fdda4ef154a31e83a" \
                       "382203c06890ab5896a05d9cfd117254ea34117b0ae6eeff576edb35b6e30acb" \
                       "5c1cfb45c1911bfdafb8c97e2fcd841f9c0b34241f4a1669776cc48727df459e" \
                       "30e65ed5dd82b723fe833d3e1c6085873af9c4d015e7781e0fe8bad6cf2e57dc" \
                       "f41e7f3b584f15880a0ca48fbc856f06852853d334f1f328be8dd9b52e2f9f3a" \
                       "d2e187ef585749d1fda06ba02b55818cbcaffff8bce89ae3aea73c4b6f27dd38" \
                       "8da09dfec2c813f9d274262e340b0dd63c629fe17e75e003b1bda516e3e8edee" \
                       "501dab1374322ea62f9088d3c10b1524a46c4c4df24ac386e74f1c415145ffd8" \
                       "e2150500b93fde8d1e1987a61a6cfae9a0736bb1aecda99eb047bc42659a213c" \
                       "995f5ed17853186c49f20e62f8c45e7d60b9cc9a941ef45652badcd8361989b9" \
                       "ecb848c46f6d7c9fe80f6534f5af2ced1631ae0c593854430d84e3fee5ab914c" \
                       "ccff1bfc5b00aaf7d0ff707587a5eaf6e547d95b0d263557431ed94b0bcfda9a" \
                       "c2b2f98675bc52e7a30da7842a179eadc2ffec7181d69799e3c991e75781caba" \
                       "2ad088d2638eecc58c2c9ea2cefbd80d883e278414bb85e8a46b9cf793d4ea26" \
                       "2609f148bfe3cde1d2dbb16eaa47a28e0b4b1ed9de45237f79c50de0b6d1ed0a" \
                       "981b86382111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                       "9da0ba073f8949d0b087f605eaf69837b22abab62eb39f0a4bb7c965a4d77887" \
                       "3c39a093fdf77f0fe1cacc5920b52cb63013fdc852c4243b48ad55b026098ac9" \
                       "65f771b5e9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                       "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                       "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                       "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                       "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                       "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                       "98675eed"
test_signature_TransferToken = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                               "3c3f3f6cf7134148dd1c73bb30e17a0451217a9cca93807bb212efcf7810a524" \
                               "909ebcd177c2d992144cc74799cfeb247a350f82e355d68dda3306e9c5b8a98c" \
                               "92ccbac14c39bb8f16fd92b81b921376cfc752122d0165f60ea1c92b9a042669" \
                               "130bd10485492dec40a349bf8308e50861f853bf7c53cc837f30d48786ff6288" \
                               "799180c1140291f6fc2151294330e957ca7b4118c28d0426a9b33f38dd41aa4b" \
                               "c29e2aeb61e46a5b6b2614d8e1520fe4fe2a48f825c7c43dc65634c4a8f808f8" \
                               "71c88aa68133b84cf491e940eb3dc15c2e64c58e58e549c9342c33f47d9dacb4" \
                               "8b1627c904db6e0b5a72fee9ec7b3d561ebad1957ddd05b357e0bc4bd5b383c2" \
                               "f7c76bd086c2a4b63d7ce9284c5de7457bf5e922a92b526a38a59d273156708d" \
                               "cab178e1c725a36fb4e60a6a2cf3d7ebc0a9c28e13669b8cd11c6e51abc66167" \
                               "35ec866ae2aebe38f657e78da69d9ea763c3e641ed1577822d25f46bd309d41d" \
                               "b946c42bccdb71f2c8a53ccefe533eaf6910f7b914cf60938d06d3d754a0224c" \
                               "6525d4a31ec5aaa0d6c1a169a6cb78f81e8293cda97bee94865f19fd36104c56" \
                               "b6bddb33c54fee608eef62c87e73e95cc2f90ec57f6e767c6ccb0d59dad60ce4" \
                               "450d777ea64beafd1833dcbb8656b3a5eac0c16fa79322944c0a7de9bfb89035" \
                               "e77e0525cbefa34dee01ad01568b3e552776be5db6c269f437e1e36e93391c47" \
                               "8f021fa94d32ea43b19df36ec76acf1476373f18dac44b582b56748d988564ff" \
                               "2253e7907b90b6d601f5f7f6f281c0c1af19b95051f979db191e38ef30b8fe2b" \
                               "933f22a189f97954f4024e96e069c7acd1e0a86b7cfad84fe50ac49a328c70aa" \
                               "994bee81d2fd49da52a7f679431421e72cf1ae2d566bf4897330e635faf68d04" \
                               "0788946e5dbae7370364607e38ceab3ad2dab36ea0f5af71b4817b19ec5a4b1c" \
                               "90fc676f63d0177f756a9bc71fdbb07b95676642419f42e80abe380a70397179" \
                               "04290a301e7cd30a1dff97489371dedc479310f5ab44b160774ceae0b93bdeb6" \
                               "9665c32c59c65de4673eea3bcb9515384f2217604735d2e81950c76f0d1a7257" \
                               "e455fe67606cd6b4a588e2c3a7d659ca7ac1f67d48902fc0eb6426909fe277fa" \
                               "12121f3d6f7974b94cee4536cdb3c9c16b984d730c90bc16b9c41ee05b4af623" \
                               "e7a853c674a1b43f43e70fd6334a562bd42fc23d26c1361c592d012e8596e1df" \
                               "fc868832f506991e91aa584308061f37d54c6210b4c0f36f44a2facc428391d2" \
                               "631ff587d82978b4b48008ea65b632e4b630edb3ed501c0fd6a157e0e6294bd7" \
                               "f3f8faf656f7daa2e11c89e66e1e13458a6e45449e2735129fde9065c010f76c" \
                               "aee607d1e8c1245a2a83fa1e1319dec769ec51f57ee3c9267f04953ca64f3f00" \
                               "2c1c235b50c00304e6cc505694325e6cbbd4cc13c5cd83b23fd544e71ad48a1d" \
                               "1a3efa613769ea1ff35f1e6f1e3ca7cefe67b9c6bf4edfd301271a71e619fa9d" \
                               "2b7a325548ec5682200636e0d74143d95614b15b4ee4a25955561913adf516d3" \
                               "d9c2aac8efb1a407da402f377584fae311bfd1719bcbfb8b1ba340a5ad9dbc2f" \
                               "fb0ebb1a6c02a89ecd1a619f9c03a3a9d238bde8ff43ba2ab4da8d2bee53892f" \
                               "4c1db3c0fa01079f2488fa794f0bb06291d2ee35c101d98fdb444ccc962b94a4" \
                               "7aeef90c88473307c743c3803fb5103544c3bcec638aa0e608211d6155d401d3" \
                               "ee3c2f83fc7b39509402116e9f6c8538b23f8ae7eea2e39dcc536bfc3d32b368" \
                               "cc5f5cc7d39084c9b29f69ee3cfbe91df63265c837a521506b23fb49555a68f7" \
                               "4af97551bd85288197896f624b334ecaab844c0c5d03bfbc5ba6dfc9bcd2cfe4" \
                               "1c472c1c6cfaf471dd726a1be1c104b61f543ae5814d19a37ae336aed7c2ae46" \
                               "1a669f31828701592686b846062f9672acecebed48b0e845e4aa4d0bb477a280" \
                               "ac5af201df42e461de58255b5f6ea3b99d40fc75063b4c307ea3982889242024" \
                               "af39330a7de40b6c5ebc7a09fd23d6456da5b731d4f197e9f71bb0eb941c8dfa" \
                               "99240e7f25554780682b385cd17eb231935b67de1a959b9a6ab8c39f14602236" \
                               "41da881cffb25ac07222cdd4e94ebdeefb38e263827f12cd36ec2479d25791a8" \
                               "5d356d1b17eda283a07466512a5f8934f968c82ce1eab75fe0141b753ec5f734" \
                               "e3d7b31e9724e6f975b6dc25d236be3faebad54d2696859166ce9838bcd73ab2" \
                               "90c3cf2bb43ddefa92f6187c63804f9da5d1266caa5eb0c5dbf4cf627adab1fa" \
                               "2a47f0ac22ceef34b458db3cd299b5d94a788c34c253bd9c9692e5a4f8e0d7b9" \
                               "09fccacb76f969d0b534bc3eb3177b858072220e25890dbdbc743708ccdd577c" \
                               "922d54cda72df1afbd39fb82def6ca756a220891258a5ad57d1566cdbfdaa432" \
                               "6eed27b5a15a8cbda4133ea016820349741d1cb2a306960b1b4fd070c03873aa" \
                               "bb82f2531c929549d940365703df97dee1bd63f2c4ac5b868ceef0b7092bcc95" \
                               "32b0c09c99fa690dddb5918a421a5bbb2aa9920e0820fbc05e39fe59d8fed991" \
                               "c161b6bf74322ea62f9088d3c10b1524a46c4c4df24ac386e74f1c415145ffd8" \
                               "e2150500e73876fe2a2092254410f197c6a8d46649d357fa3c99baf3195f94e0" \
                               "88121b8bbbe90bab077889929793059ba26a7f0862c463282e36601e0582c99b" \
                               "d8dbb163889b8cb5372d62e2b32217e83d408d3e70d0127d3b7dbd382331c832" \
                               "eb52f249c9941cb00c9e1a5fd53004439a1cf353e14fe4912f07e2822ae81ae6" \
                               "cd5d8b6570fd0c5e4d131487e738a50ed0ff9e96b8d35110503d06b7960c0d01" \
                               "a955d51063c1eb1088e8abd247c2aa2602c7e4f3c770cff184cef51c0b2a79aa" \
                               "ceb82c7a9879157f1c9722c2d00b28452c606037156bcaf68cbbc8f6d4fd371a" \
                               "1acc0ed92111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                               "9da0ba079a934ab085b2fd6dd340ec31e77a1aff6cc586730264da3232b3aa5f" \
                               "2bd2a25475de043174eb1cf8e3a1494e094c5583986106e7c0349874555b4eab" \
                               "8896a80ce9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                               "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                               "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                               "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                               "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                               "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                               "98675eed"
test_signature_MessageTransaction = "0000000a899e73cfbf8c57027f5a0f853b9906701ee378ad169d34ce45153f13" \
                                    "3c3f3f6c870ead6e875c470543e9e91ab30e6119251698511ddd403c98167317" \
                                    "78adc7495d8f176dc9d0d5b9e08bf6314933cd1fc630ee0e0deddf477c22220d" \
                                    "61b3a78be588ce819a27523ef24066365a4156a1f809d7a47e047f99888a4998" \
                                    "43fbbab755571dc4bd2201c87488c1c68162ebf51b59576a4c0cfdf034f2ab32" \
                                    "9dc15734ae64db7bfde2193accc7c7d2befc43db6aabd428dc25d79d8e10f837" \
                                    "cc1c47bfcda52aaeabc57d1f3e7e741144616fff91ffd7c511f62e2980e32480" \
                                    "9d8afa822d1c1eac26d137e6b395b3deec26b1e66b543cbcb261eab981f5ac7b" \
                                    "e9d210fa04db6e0b5a72fee9ec7b3d561ebad1957ddd05b357e0bc4bd5b383c2" \
                                    "f7c76bd023081d4cf81a48f903b3218df7284e06d2b65b2083a472ca7888ffbc" \
                                    "c9ebaf6fc725a36fb4e60a6a2cf3d7ebc0a9c28e13669b8cd11c6e51abc66167" \
                                    "35ec866a0061c1db1c98a647fc68b783de0d226a47cc0305feea9d5611301611" \
                                    "b133ef6a3f44e75e5ec8b4f579e8b7795d61885ad5cc9f0d217eb494607ef7b2" \
                                    "d058fe304b59740ee4218418de0e1ca08a998017c7a2e3325331da38354b58a2" \
                                    "35b6734f6d6f52a2499a97a278ace169e897f98260c4342c9595d33897b838fe" \
                                    "4a320f42f407cdafe217809d5829b6ada1156691ee5421d23a1df25e0fda84fa" \
                                    "98fabd432e354a339e4e4526da6a79fe77c30ba86ef988c57832dded50efd9b7" \
                                    "3788c077fa8e049cb717eb8e241381048a14ef790a218d3ae02ca8aac3d33832" \
                                    "27cd2ae97da6a2c091f82a98cb7ab34c2e49541714ee9f55b3963d7ee8f1f870" \
                                    "73fbc5c72c4a070a10873e47477fd5dc35362de92cb72f9becf1e67a9130473f" \
                                    "91ad4e12ae89ec1c00c2805c0615cfccc2dfbb47cfd6340478ce75955e93b16e" \
                                    "a0ee11b72d3c9f0eac99611115c52e002470e43f95a1fa7b666263eebdc3433e" \
                                    "68be9534c2e46ab5d70bc9647f4f39bdae35ad32bcebaf7548b5de91eca8126d" \
                                    "04f350e97f8aaca80dc5a1fa74681f4afd38568b123ef00b90da1c5853009e95" \
                                    "d81ece892977c1f43367acc0895af37a68753aee0a1f06548a2f46f448b92915" \
                                    "5511821bcd66230cc66762902dd7c2c103738c6f4d3c263509b817bda60cf058" \
                                    "e93a814101f3129f705ec5c39cda0a7dce4616631b044089645245caecec689f" \
                                    "e59e3efb3e1a9028d2732b0058616706d79cb9169044072922c8cbad8cc56b5b" \
                                    "2a14dfd653fe1a494534e4c9117c48b3916843dc5252b5bdb56bb5d9effe5819" \
                                    "d22174e563effe6799809f08a464c9aa564992b412baa6578dc2f1f91697672f" \
                                    "7c9015ccc4f291c54c0e2e8b100579663f61fbe5adc5e2c4e295244bd58e6e75" \
                                    "b6df3284547f331d3af8842d333d24b0e4e80a2b49c284e83161035740dbd228" \
                                    "4ba98bdc97498ad0084139243cc3b553a38dde0855c5d487d8c4ecbaebf75186" \
                                    "e40deeee8a3d7a27b8cf486226d24253577d374cffa7a2a8172464249e0cc00d" \
                                    "a1f83a0b45df768c4cbe929cabe866e19c6fb7fbbf6c3e9cd6c72e38cef02aef" \
                                    "10aec1d53f92c5df896df6010091c6d6fdd30621c9ac62225e38abfe6757830b" \
                                    "d2019a58653524a6be818e1b7b55021a579dacacfdde0854959da4e844f89381" \
                                    "a36aaa61f5dc742c7539f8cfd3097e0c717046dd0bd3a181fe0f04efe03ed445" \
                                    "f35b75629d72c4e561591279bf5373aa44ae6b71aee6dc0c29c2604af7f09758" \
                                    "ff7616a30c7a84744d291a259b6a44d739261311f570bd2721336adfb5189a8a" \
                                    "103a928e7edf9560143cb7f5a48feb24a6269452f0f0e1873c2ecf33c4812bdf" \
                                    "89ab96f53505c6d74f4f68517e012cc08b22df1c152edb71b441690b6b668639" \
                                    "ef22c9efb6f9db8b1a82d44b515f8ac08242cb09a994991403b4a593d5e4954d" \
                                    "50a36a57828701592686b846062f9672acecebed48b0e845e4aa4d0bb477a280" \
                                    "ac5af201b9b1e4ee22b4602b1360c30888a898ac43fcec032b803972a9e3dd11" \
                                    "bb120e66f74054f47d4c8ff621b8057bb6a3e4b58c6557f1bd9294cdcf65a8eb" \
                                    "a149ab71a2784ba462a8e0856890d9bce6d2dab26ac4e8dbf6f09fba7e06516e" \
                                    "04dfc4fa080fcdb9d01851cbd8b3986edb072ceb3e86cf18d01b52bffc2ba338" \
                                    "a8e4f8a2b8f3a1062ab65f2f70441d216d61e0eea7ba860ec539376ae0899f51" \
                                    "e784efa6bfc87d4c75c0b736acc124f9d0246b5ab407914add2388a1e5c4840e" \
                                    "a812da2e50a73e1448d89f79f3e2d6d20568bb9570b601484c9c61df1a688fe0" \
                                    "ec19dfe66890ab5896a05d9cfd117254ea34117b0ae6eeff576edb35b6e30acb" \
                                    "5c1cfb45846ca40249e396ad31b467eef233c0556dd0edf50ff06e2d9bdf622e" \
                                    "0a69b4da1be4bc00f55f559b4fc6c88d929268fc17d4ecf2764439f5c876e592" \
                                    "e911e3304c865738003144d26d6bf41afecba096b8e9994a4d39bcf6d2aad4ff" \
                                    "5d928027c07922d4cf4b3a04acfb552c502f17efc652606009fcc255ed89af79" \
                                    "d3545f1f56e316ccfb89d26dc9012461bb838f90e179e6e08ece20d97ee60a1c" \
                                    "576fba51c174746b3155dd65f4b5b240621f186092f30bd3ae5cf98c15747a47" \
                                    "67c87a53cbafb7a0f79cf25765fd2c32e54481111b0ea5f625031788bcfcafa9" \
                                    "e6645409415a1c56c217c26149fd945c6b6f702637333950a3e441656daf460a" \
                                    "782ded93a118a09b25fde1e26d467d1e5f7c81511c4aee2e61f5c0bc263ec5ac" \
                                    "0f9c4b1dd7d7cc5d477b36534b92ac64f148cda22642434e4f72100729b4582f" \
                                    "8877ae4370fd0c5e4d131487e738a50ed0ff9e96b8d35110503d06b7960c0d01" \
                                    "a955d51063c1eb1088e8abd247c2aa2602c7e4f3c770cff184cef51c0b2a79aa" \
                                    "ceb82c7ab641bc5e699b5bb6862c5ddf3630c1d48260147be335595b1d96dcc5" \
                                    "bf3387112111ea986fd011fe4b0d9c728c5ef5d30eb1e175aed1b8881c7fc396" \
                                    "9da0ba072b95661816920f809e6dd85a25918405e531860ce3f905fe41cc0552" \
                                    "1885294e4c7471870ca5410593692f9cbd06d82cd86dc9cef94339cee4bd1548" \
                                    "f91ecc21e9bc647fcd24bc50d3d0ab41b9997cc3371db8c742bde679e67ed775" \
                                    "e14296218d9e075ae892eb5bb3e8e41568ab594809f2bc173a38649123a86dc6" \
                                    "a9f58e48ef5c2c90feccc6a6b1f3f90bcbf233bd0347d4c95b1818c93fe7f250" \
                                    "5252d9176958b64cc5a7a6c2b99b6adebc3a66e3c07d2343ec0072fc32645100" \
                                    "95b34ebe7f09870e34e155ef3c2c542bfff412c7d6b6f6fc90b0a95a635eed0f" \
                                    "a50a126a5d24b78c915c210dbf5e92633f83f282d0b9e4e0a47f49f3d3249828" \
                                    "98675eed"
wrap_message_expected1 = bytearray(b'\xff\x00\x0000000027\x00{"data": 12345, "type": "TESTKEY_1234"}\x00\x00\xff')
wrap_message_expected1b = bytearray(b'\xff\x00\x0000000027\x00{"type": "TESTKEY_1234", "data": 12345}\x00\x00\xff')
