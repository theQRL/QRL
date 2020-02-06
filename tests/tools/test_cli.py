# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import json
import os
import shutil
import tempfile
from unittest import TestCase, mock

from click.testing import CliRunner

from qrl.cli import qrl as qrl_cli
from qrl.core import config
from qrl.core.misc import logger
from qrl.generated import qrl_pb2

logger.initialize_default()

unsigned_tx = b"\nOQ010200be640405bb61d104e329cc94b6807b6e713ef0dea80aa5aa73abff8dd88946b41172569c\x1aC\x01\x02\x00\x80\x9dg/U\xb1N\xf2_\x0e~j%\xb2\x15\x05\xa7y\x19\x8f\xc0>\x05`\x90\xe3>\xaa\x9a(\xd3\xc7U\x91\xbab\x90{\xaa^\xadQ\xca\xbf\xd3\xbc\xd9\x93\xf0:D\xca\xd8v\x97\x08\xa8x\x9c-\n4\xd6e:,\n'\x01\x04\x00\xd9\xf1\xef\xe5\xb2r\xe0B\xdc\xc8\xefi\x0f\x0e\x90\xca\x8b\x0bn\xdb\xa0\xd2o\x81\xe7\xaf\xf1*gT\xb2\x17\x88\x16\x9f\x7f\x12\x01\x00"  # noqa
bin2hstr_unsigned_tx = '1a4301030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada3565854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e3a8c010a2701050000a31343e48abce29464f063b30827ecf2c552743cab13d4f3b457b55410b548a0f8bca60a270105009ca50ed86497e6b2cfcca8c525191c741220eacf79a697e078bf9b53a9899b17b3f839d10a27010500e135decb3328a27e51c47064df2dbbe799e79812291cc5e7cfad08a82a62d64e4fa813aa120f8094ebdc0380a8d6b90780bcc1960b'  # noqa
bin2hstr_unsigned_tx2 = '0a2701050000a31343e48abce29464f063b30827ecf2c552743cab13d4f3b457b55410b548a0f8bca61a4301030038ea6375069f8272cc1a6601b3c76c21519455603d370036b97c779ada3565854e3983bd564298c49ae2e7fa6e28d4b954d8cd59398f1225b08d6144854aee0e3a2c0a270105009ca50ed86497e6b2cfcca8c525191c741220eacf79a697e078bf9b53a9899b17b3f839d1120100'  # noqa
bin2hstr_signed_tx = '0a4f513031303230306265363430343035626236316431303465333239636339346236383037623665373133656630646561383061613561613733616266663864643838393436623431313732353639631a43010200809d672f55b14ef25f0e7e6a25b21505a779198fc03e056090e33eaa9a28d3c75591ba62907baa5ead51cabfd3bcd993f03a44cad8769708a8789c2d0a34d6652284120000000064c5a87881bca5010aef4363de5ebc4452cbd585f9e3aefb12f2b3680eb9fcaac1c8d30d002d0b7818d6ec7e2bf6fc9e489d2b7f621ff9d4213420d19d7a00798c4a730ab34594f7042e757a066d66cfd9eac5d4b201692657a8ae14584833468b45b2229c1f8a056da8522ae84a1f8628df94707d4b495e2775e7f75847113568c0e13fc15669212599cbaf8b574afe19a77644af08fc1a48ea6333036bd9e2fb6b0afc6a70cc696ba27e38f79e6a3337bfc21369112609cb309495056255ac439afecda65094c1e159eb35e476b660b05fa05b0e719f48e1c77ca8c816c070bc2efda0affcf5a5ebcd73861b00a2240e722047c26ba71193551b9b30bf95dad62b068f8ef4ef663de2298461cbb57330ec94ed06c0e33f7c5e9137815f5e3ce8cc446e7fc8b5b97339d1ba21381ac341a479f2905659f02b80b7ed4adae605d2e17ece9523fe8e4bacfde8db6c9a8f87abf14492384b4b0b9118d76102458709e468bdb600147abbb70421d4b83c38ed763da8524168d1aa6ac5be25fa9e3f8fbba814e604f55927fc82dd8775b1bbde8bbded783adf8e608a3dbdbf76c4b38e35128a405ecabb4d49243ff79de6d91ac8d14205a9a3164bc4dc3768b705e0c2a1a21411a2bba1cbd38d5eee55392edfce30d4e3a328e413b2e28adb5bb83a9c634d7e043ac19a493c9a69a2bd2b24c3061c84d0249b7f921074689774fcc5852e4dc6658be3ce323ba54ab5fb3315791f8277f3cc8fcac3d07a981557873aadc5193d76a6d1a312ecb11bd8546b3912dc57deab8536d2978ab46452dd8e1a18a2f136916a9a311f5b4ad37a9e5e502a6fda1728cebcbd0db8c2cff7ce557cb7e30961969ee594defc6e681cab251c2136d85f858ef17444cc561461cf07b43c62edc85f040ad8b72ff5bf06c4668828916cb9531b3d1c12cdcab6ac3e66038653906e299ade2ef317d11584db67e38c2624270343ea5519b90dc4861382a5b3b512cc97fa4d10fb787cf535c0daeff9e291d91cd295fada168e733f4dc57b827ccf0a8f3401f46900f32fe5d349d7e482861794757364ef7b4935238d0612cb5a9dde434c75646226303f83c600d8186c1aca157b568a41f70925d86f8ecfe4458bd09551df2282281f4e3f63ed675d67fb297457c27fea54327008c56a4c60668c5251f788d29198daade91f9c4c5c46e043f498402982614b02ed5a2711b02bc85c9a60bdf384a51b801fb08c07720f3cf17a03a8c0f43f9490f39264f818893fe0bb263793d752f5756fcd9f0ed023cccc2046c6b7fb1bceb61ae33006ad44f16f3b1e730b25c0c7b6642505349374d90a53fff31ab89fa16795d10cbe46bbfd89b45854a70f5993e2c6a51cd1dab64e1bfc678d09b0e4e1960647ef16c478ff35d332e6d2e45d6443f85a5dc6197d66b250e9b17cb7249cb318285a6c1cbcc7dc05f5f0b4ea2c2a088c9cfde004ad8dc35aedce3bb47195b5a6550fcd5421e8f67c9d750e46b1ca27f3b1128a9afe10755f42bd5d099ec9d9e8c30adfa28e37164aa0278404f576d2598662da6b3c533f95f646ad775265a28e78d90e6f518f11d95703e40ab8235dbdefe2ba7f5e7ce576ef0e50a9ea306e07177d8aac049f00c45e0d5eb3a7fd3821d2010700548b3852861988ba234036ef88ba855c33bef9447f7ede60b3cd27b0645b82b579c566a1b777680ff3bbdc727bbac0d92afb650403c74f92f9b33a4435a52f8d36aae8724cdd4934a5d9c3ee0bedfd7b06b8e0a4491c73752c5edec412d5c138f965ce5d08eb0db5dbd1eb78b1df6419d66b37ac837bfbef9ad5cce68ba4c1d85b92cec21f559c19efaf45eaa13179e4db26cfd03bbc187c5c2aadd2a506b1c498fde3dee3b221304527b351e23000b870b41dec03f4436e2ee4115e5ddfafc27aa9066e517527da6ed70f9a39f6267f8a7e1824660538861e10d337f8fa62bfdd1b4db957405243166ea4f4fa19e9831f657b87d8ccccc69042a26909a95701f235a78b63966a34959d55e40bc1bb1ec8df2da92b9bafa4ed39ea31b5d115c810211ecd09e62752e5151d4e517bd6e96455cc45ca93200bbf6046242c4c520ec6b9a707e885a3cead56d68aa0f2ee1ffa6e971a5851b910a200153fc143f8f5e440df12147bd2876349a9a06b81bf8bf71478f9a3914d2924da6afa2a0dc0e102d75e2e54fcea2c5ea267908a2f2e0385cd28316a3131791724998b49395d84fb0cfec0d44de3396dd145e3e5c75e0242c5384eac34a89159b5849736ee817a3f7dc08bb1508e03a2596321b06ba55689e846d614ca985e6f658f1601c4d86ae12e015755ddec13a14ae7e021c9eb478e9dec8eac921b2c4b297a01b9f424467c74d27f9dca4423b57d6489e9d50d54f505f387e5b4bf520b6b137f992d14582b633054f15968a6615441886d5d05ac143f8dab0efb8a05bae6d46093e213255f560e22212f1303abf04e599b1186133796d9da5a5dd7a5c01a44cb159a228bf6503c925944d6140fe2b85d0f6ddcf046e41d824eb111e7a15c8a2cbdbc47ab6a75573b0b5f69e8af66ca4fcfeb612bdf516dba5326565777e0754ec08ba703f433cd022ee5c77a5e3dbe6af7f28255176019e68dc4cca50436cb230abf304d60864e51614d057f97c96d81773c2a3ef2f358e8ca0aedb22496280cbe727c188579d250222c7f2e56e7ab2d6c7c6d22cd8d342586407930e1898d5b16c55b3ec37bb5c6757804523072175c931d735c819803d14394ec244bfc6f36bc9d0b35438654169030f52addb175aa7a047e876bacd8cbc763cd0cce8734f9526150964e5977742fc9ddf9864336ea51dacb7a8838f840c92f41550dbbae71a7d83e6fc2308914e19fe20a75cb01d5a6a151c7b553c76ef72592136c0ebf91ca13c5725ec8dd302968708bc7662808e2e5cd93729cb5d0923f948182c897d2848491a8e3bdb4a769894e89d1c32e765daeb5f49d5ddae5291c351a3d4ba2944c99c1f120da2e485e88f0fb43af2aa4099508a043efe5e634eb05bdcbfae42a9b0b6a7918d0f7cac85c715947c48a3c7386def94a24dd9c7122a41575d574588b2b8ca41434bbd77aab3435000983597b6a91fee20bceb5243a652fffb2edb1156f50dde388ae8595b7f7ba93f514b35038509e71f51ad07077da504781dec62f7053d3976b5ab6e852b41331af42528ba9167eb013c902f6d0a8638b75f06957d1a03633bec8e81ea7617f46279752d204c532203fa9394bf4b643d8140cb6179d8d0a9aba1f4c3151c3daa05bea571346bffe793a2c0a27010400d9f1efe5b272e042dcc8ef690f0e90ca8b0b6edba0d26f81e7aff12a6754b21788169f7f120100'  # noqa

qaddr_1 = "Q01050000a31343e48abce29464f063b30827ecf2c552743cab13d4f3b457b55410b548a0f8bca6"
qaddr_2 = "Q0105009ca50ed86497e6b2cfcca8c525191c741220eacf79a697e078bf9b53a9899b17b3f839d1"
qaddr_3 = "Q010500e135decb3328a27e51c47064df2dbbe799e79812291cc5e7cfad08a82a62d64e4fa813aa"
qaddr_4 = "Q0105001fa3a2038c0b4b947cccbf589d53fc7749f0a04f118ec1ffadedd1b4db37e83c513aa259"


def open_wallet(filename="wallet.json"):
    with open(filename) as f:
        return json.load(f)


@mock.patch('qrl.cli.grpc.insecure_channel', new=mock.MagicMock())
class TestCLI_Wallet_Gen(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCLI_Wallet_Gen, self).__init__(*args, **kwargs)

    def setUp(self):
        self.runner = CliRunner(env={"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
        self.prev_dir = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()

        os.chdir(self.temp_dir)

    def tearDown(self):
        del self.runner  # running this test suite often results in leaked pipe handles. This could mitigate that.
        os.chdir(self.prev_dir)
        shutil.rmtree(self.temp_dir)

    def wallet_gen_default_height(self):
        result = self.runner.invoke(qrl_cli, ["wallet_gen"])
        wallet = open_wallet()
        self.assertIn(self.temp_dir, result.output)
        self.assertEqual(wallet["addresses"][0]["height"], 12)

    def test_wallet_gen_different_height(self):
        result = self.runner.invoke(qrl_cli, ["wallet_gen", "--height=4"])
        wallet = open_wallet()
        self.assertIn(self.temp_dir, result.output)
        self.assertEqual(wallet["addresses"][0]["height"], 4)

    def test_wallet_gen_different_hash_function(self):
        result = self.runner.invoke(qrl_cli, ["wallet_gen", "--height=4", "--hash_function=sha2_256"])
        wallet = open_wallet()
        self.assertIn(self.temp_dir, result.output)
        self.assertEqual(wallet["addresses"][0]["hashFunction"], "sha2_256")

    def test_wallet_gen_json(self):
        result = self.runner.invoke(qrl_cli, ["--json", "wallet_gen", "--height=4"])
        self.assertTrue(json.loads(result.output))  # Throws an exception if output is not valid JSON

    def test_wallet_gen_encrypt(self):
        result = self.runner.invoke(qrl_cli, ["wallet_gen", "--height=4", "--encrypt"], input='password\npassword\n')
        wallet = open_wallet()
        self.assertIn(self.temp_dir, result.output)
        self.assertTrue(wallet["encrypted"])


@mock.patch('qrl.cli.grpc.insecure_channel', new=mock.MagicMock())
class TestCLI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCLI, self).__init__(*args, **kwargs)

    def setUp(self):
        self.runner = CliRunner(env={"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
        self.prev_dir = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()
        os.chdir(self.temp_dir)
        self.runner.invoke(qrl_cli, ["wallet_gen", "--height=4"])

    def tearDown(self):
        os.chdir(self.prev_dir)
        shutil.rmtree(self.temp_dir)

    def test_wallet_ls(self):
        result = self.runner.invoke(qrl_cli, ["wallet_ls"])
        wallet = open_wallet()
        self.assertIn(wallet["addresses"][0]["address"], result.output)
        self.assertIn(self.temp_dir, result.output)  # You should know which wallet you've opened.

    def test_wallet_ls_verbose(self):
        result = self.runner.invoke(qrl_cli, ["-v", "wallet_ls"])
        wallet = open_wallet()
        self.assertIn(wallet["addresses"][0]["hashFunction"], result.output)

    def test_wallet_ls_empty(self):
        os.remove("wallet.json")
        result = self.runner.invoke(qrl_cli, ["wallet_ls"])
        self.assertIn("No wallet found", result.output)

    def test_wallet_ls_json(self):
        result = self.runner.invoke(qrl_cli, ["--json", "wallet_ls"])
        wallet = open_wallet()
        self.assertTrue(json.loads(result.output))  # Throws an exception if output is not valid JSON
        self.assertIn(wallet["addresses"][0]["address"], result.output)
        self.assertIn(self.temp_dir, result.output)  # You should know which wallet you've opened.

    def test_wallet_add(self):
        result = self.runner.invoke(qrl_cli, ["wallet_add", "--height=4"])
        wallet = open_wallet()
        self.assertIn(wallet["addresses"][1]["address"], result.output)
        self.assertEqual(wallet["addresses"][1]["height"], 4)

    def test_wallet_add_inherit_encryption_status(self):
        self.runner.invoke(qrl_cli, ["wallet_encrypt"], input='password\npassword\n')
        self.runner.invoke(qrl_cli, ["wallet_add", "--height=4"], input='password\n')
        wallet = open_wallet()
        self.assertTrue(wallet["encrypted"])

    def test_wallet_add_different_hash_function(self):
        self.runner.invoke(qrl_cli, ["wallet_add", "--height=4", "--hash_function=shake256"])
        wallet = open_wallet()
        self.assertEqual(wallet["addresses"][0]["hashFunction"], "shake128")
        self.assertEqual(wallet["addresses"][1]["hashFunction"], "shake256")

    def test_wallet_recover_hexseed(self):
        os.rename("wallet.json", "wallet_orig.json")
        wallet_orig = open_wallet("wallet_orig.json")
        self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=hexseed"],
                           input='\n'.join([wallet_orig["addresses"][0]["hexseed"], 'y']))
        wallet_recovered = open_wallet()
        self.assertEqual(wallet_recovered, wallet_orig)

    def test_wallet_recover_hexseed_invalid_input(self):
        os.rename("wallet.json", "wallet_orig.json")
        wallet_orig = open_wallet("wallet_orig.json")
        result = self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=hexseed"],
                                    input='\n'.join([wallet_orig["addresses"][0]["hexseed"] + "deadbeef", 'y']))
        self.assertIn('Hexseed must be of only', result.output)
        self.assertFalse(os.path.exists("wallet.json"))

        # If the recovered address is already in the wallet, it should react in this way.
        self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=hexseed"],
                           input='\n'.join([wallet_orig["addresses"][0]["hexseed"], 'y']))
        result = self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=hexseed"],
                                    input='\n'.join([wallet_orig["addresses"][0]["hexseed"], 'y']))
        self.assertEqual(result.exit_code, 0)
        self.assertIn('Wallet Address is already in the wallet list', result.output.strip())

    def test_wallet_recover_mnemonic(self):
        os.rename("wallet.json", "wallet_orig.json")
        wallet_orig = open_wallet("wallet_orig.json")
        self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=mnemonic"],
                           input='\n'.join([wallet_orig["addresses"][0]["mnemonic"], 'y']))
        wallet_recovered = open_wallet()
        self.assertEqual(wallet_recovered, wallet_orig)

    def test_wallet_recover_mnemonic_invalid_input(self):
        os.rename("wallet.json", "wallet_orig.json")
        wallet_orig = open_wallet("wallet_orig.json")
        result = self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=mnemonic"],
                                    input='\n'.join([wallet_orig["addresses"][0]["mnemonic"] + " bad", 'y']))
        self.assertIn('Mnemonic seed must contain only 34 words', result.output)
        self.assertFalse(os.path.exists("wallet.json"))

        # If the recovered address is already in the wallet, it should react in this way.
        self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=mnemonic"],
                           input='\n'.join([wallet_orig["addresses"][0]["mnemonic"], 'y']))
        result = self.runner.invoke(qrl_cli, ["wallet_recover", "--seed-type=mnemonic"],
                                    input='\n'.join([wallet_orig["addresses"][0]["mnemonic"], 'y']))
        self.assertEqual(result.exit_code, 0)
        self.assertIn('Wallet Address is already in the wallet list', result.output.strip())

    def test_wallet_secret(self):
        wallet = open_wallet()
        result = self.runner.invoke(qrl_cli, ["wallet_secret", "--wallet-idx=0"])
        self.assertIn(wallet["addresses"][0]["address"], result.output)
        self.assertIn(wallet["addresses"][0]["mnemonic"], result.output)
        self.assertIn(wallet["addresses"][0]["hexseed"], result.output)

    def test_wallet_secret_encrypted(self):
        wallet = open_wallet()
        self.runner.invoke(qrl_cli, ["wallet_encrypt"], input='password\npassword\n')
        result = self.runner.invoke(qrl_cli, ["wallet_secret", "--wallet-idx=0"], input='password\npassword\n')
        self.assertIn(wallet["addresses"][0]["address"], result.output)
        self.assertIn(wallet["addresses"][0]["mnemonic"], result.output)
        self.assertIn(wallet["addresses"][0]["hexseed"], result.output)

    def test_wallet_secret_encrypt_decrypt_wrong(self):
        wallet = open_wallet()
        self.runner.invoke(qrl_cli, ["wallet_encrypt"], input='password\npassword\n')
        result = self.runner.invoke(qrl_cli, ["wallet_secret", "--wallet-idx=0"], input='password\npassword\n')
        self.assertIn(wallet["addresses"][0]["address"], result.output)
        self.assertIn(wallet["addresses"][0]["mnemonic"], result.output)
        self.assertIn(wallet["addresses"][0]["hexseed"], result.output)

        result = self.runner.invoke(qrl_cli, ["wallet_decrypt"], input='wrong_password\nwrong_password\n')
        self.assertEquals(1, result.exit_code)
        # TODO: Add appropriate error matching

    def test_wallet_secret_invalid_input(self):
        result = self.runner.invoke(qrl_cli, ["wallet_secret", "--wallet-idx=2"])
        self.assertEqual(result.output.strip(), 'Wallet index not found 2')

    def test_wallet_rm(self):
        self.runner.invoke(qrl_cli, ["wallet_add", "--height=4"])
        wallet = open_wallet()
        result = self.runner.invoke(qrl_cli, ["wallet_rm", "--wallet-idx=1", "--skip-confirmation"], input='y\n')
        self.assertNotIn(wallet["addresses"][1]["address"], result.output)
        result = self.runner.invoke(qrl_cli, ["wallet_rm", "--wallet-idx=0"], input='y\n')
        self.assertIn("No wallet found", result.output)

    def test_wallet_rm_invalid_input(self):
        result = self.runner.invoke(qrl_cli, ["wallet_rm", "--wallet-idx=2", "--skip-confirmation"], input='y\n')
        self.assertEqual(result.output.strip(), 'Wallet index not found 2')

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_state(self, mock_stub):
        m_node_state_resp_serialized_to_string = b'\n/\n\x160.61.3+ngbd52b1a.dirty\x10\x03\x18\x02 D(\xa7\x010\x83!B\tExcession'
        m_node_state_resp = qrl_pb2.GetNodeStateResp()
        m_node_state_resp.ParseFromString(m_node_state_resp_serialized_to_string)

        mock_stub_instance = mock.MagicMock(name='this should be qrl_pb2_grpc.PublicAPIStub(channel)')
        mock_stub_instance.GetNodeState.return_value = m_node_state_resp

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        result = self.runner.invoke(qrl_cli, ["state"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('Excession', result.output)

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_state_json(self, mock_stub):
        m_node_state_resp_serialized = b'\n/\n\x160.61.3+ngbd52b1a.dirty\x10\x03\x18\x02 D(\xa7\x010\x83!B\tExcession'
        m_node_state_resp = qrl_pb2.GetNodeStateResp()
        m_node_state_resp.ParseFromString(m_node_state_resp_serialized)

        mock_stub_instance = mock.MagicMock(name='this should be qrl_pb2_grpc.PublicAPIStub(channel)')
        mock_stub_instance.GetNodeState.return_value = m_node_state_resp

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        result = self.runner.invoke(qrl_cli, ["--json", "state"])
        print(result.output)
        print(result.exc_info)
        self.assertEqual(result.exit_code, 0)

        the_output = json.loads(result.output)
        self.assertEqual(the_output["info"]["networkId"], "Excession")

    @mock.patch('qrl.cli.config', autospec=True)
    @mock.patch('qrl.cli.Transaction', autospec=True)
    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_slave_tx_generate(self, mock_stub, mock_transaction, mock_config):
        # Mock out xmss_tree_height so this test runs faster!
        # But first, we must copy all attributes from the real config into the mock.
        # autospec does not do this for us, only the specification.
        mock_config.configure_mock(**config.__dict__)
        mock_config.dev.xmss_tree_height = 4

        mock_tx_attrs = {"name": "a mock tx object", "to_json.return_value": "{}"}
        mock_tx = mock.MagicMock(**mock_tx_attrs)

        mock_transaction.name = 'mock Transaction class'
        mock_transaction.from_pbdata.return_value = mock_tx

        mock_slave_txn_resp = mock.MagicMock(name='mock slaveTxnResp')
        mock_slave_txn_resp.extended_transaction_unsigned.tx = bin2hstr_unsigned_tx

        mock_stub_instance = mock.MagicMock(name='this should be qrl_pb2_grpc.PublicAPIStub(channel)')
        mock_stub_instance.GetSlaveTxn.return_value = mock_slave_txn_resp

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        wallet = open_wallet()
        master_address = wallet["addresses"][0]["address"]

        # Simplest use case
        result = self.runner.invoke(qrl_cli, [
            "slave_tx_generate", "--src=0", "--master={}".format(master_address),
            "--number_of_slaves=1", "--access_type=0", "--fee=0"
        ])
        print(result.output)
        print(result.exc_info)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.exists('slaves.json'))

        # Does it work with 5 slaves?
        os.remove('slaves.json')
        result = self.runner.invoke(qrl_cli, [
            "slave_tx_generate", "--src=0", "--master={}".format(master_address),
            "--number_of_slaves=5", "--access_type=0", "--fee=0"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.exists('slaves.json'))

        # access_type could be 0 or 1. test 1.
        os.remove('slaves.json')
        result = self.runner.invoke(qrl_cli, [
            "slave_tx_generate", "--src=0", "--master={}".format(master_address),
            "--number_of_slaves=5", "--access_type=1", "--fee=0"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.exists('slaves.json'))

    @mock.patch('qrl.cli.config', autospec=True)
    @mock.patch('qrl.cli.Transaction', autospec=True)
    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_slave_tx_generate_invalid_input(self, mock_stub, mock_Transaction, mock_config):
        mock_config.configure_mock(**config.__dict__)
        mock_config.dev.xmss_tree_height = 4

        mock_tx_attrs = {"name": "a mock tx object", "to_json.return_value": "{}"}
        mock_tx = mock.MagicMock(**mock_tx_attrs)

        mock_Transaction.name = 'mock Transaction class'
        mock_Transaction.from_pbdata.return_value = mock_tx

        mock_slaveTxnResp = mock.MagicMock(name='mock slaveTxnResp')
        mock_slaveTxnResp.extended_transaction_unsigned.tx = bin2hstr_unsigned_tx

        mock_stub_instance = mock.MagicMock(name='this should be qrl_pb2_grpc.PublicAPIStub(channel)')
        mock_stub_instance.GetSlaveTxn.return_value = mock_slaveTxnResp

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        wallet = open_wallet()
        master_address = wallet["addresses"][0]["address"]

        # It shouldn't allow > 100 slaves.
        result = self.runner.invoke(qrl_cli, [
            "slave_tx_generate", "--src=0", "--master={}".format(master_address),
            "--number_of_slaves=101", "--access_type=0", "--fee=0"
        ])
        self.assertNotEqual(result.exit_code, 0)
        self.assertFalse(os.path.exists('slaves.json'))

        # # Access types other than 0, 1 shouldn't work
        # result = self.runner.invoke(qrl_cli, [
        #     "slave_tx_generate", "--src=0", "--master={}".format(master_address),
        #     "--number_of_slaves=1", "--access_type=2", "--fee=0"
        # ])
        # self.assertNotEqual(result.exit_code, 0)
        # self.assertFalse(os.path.exists('slaves.json'))

        # Negative fees shoudn't work.
        result = self.runner.invoke(qrl_cli, [
            "slave_tx_generate", "--src=0", "--master={}".format(master_address),
            "--number_of_slaves=1", "--access_type=0", "--fee=-1"
        ])
        self.assertNotEqual(result.exit_code, 0)
        self.assertFalse(os.path.exists('slaves.json'))

    def test_tx_inspect(self):
        result = self.runner.invoke(qrl_cli, ["tx_inspect", "--txblob", bin2hstr_unsigned_tx])
        self.assertTrue(json.loads(result.output))

    def test_tx_inspect_invalid_input(self):
        result = self.runner.invoke(qrl_cli, ["tx_inspect", "--txblob", bin2hstr_unsigned_tx[2:]])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('is not valid', result.output)

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_push(self, mock_stub):
        mock_error_code = 'Error? What error? This is a test'
        mock_push_transaction_resp = mock.MagicMock(name='this should be pushTransactionResp',
                                                    error_code=mock_error_code)

        attrs = {"name": "this should be stub.PushTransaction",
                 "PushTransaction.return_value": mock_push_transaction_resp}
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        result = self.runner.invoke(qrl_cli, ["tx_push", "--txblob", bin2hstr_signed_tx])
        self.assertIn(mock_error_code, result.output)

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_push_invalid_input(self, mock_stub):
        mock_error_code = 'Error? What error? This is a test'
        mock_push_transaction_resp = mock.MagicMock(name='this should be pushTransactionResp',
                                                    error_code=mock_error_code)

        attrs = {"name": "this should be stub.PushTransaction",
                 "PushTransaction.return_value": mock_push_transaction_resp}
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        # txblob should already be signed
        result = self.runner.invoke(qrl_cli, ["tx_push", "--txblob", bin2hstr_unsigned_tx])
        self.assertEqual(result.exit_code, 1)
        self.assertIn('Signature missing', result.output)

        # It should choke on invalid txblobs
        result = self.runner.invoke(qrl_cli, ["tx_push", "--txblob", bin2hstr_signed_tx[2:]])
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.output.strip(), 'tx blob is not valid')

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_transfer(self, mock_stub):
        tx_pbdata_serialized_to_string = b"\n\x02\\n\x1aC\x01\x02\x00\x80\x9dg/U\xb1N\xf2_\x0e~j%\xb2\x15\x05\xa7y\x19\x8f\xc0>\x05`\x90\xe3>\xaa\x9a(\xd3\xc7U\x91\xbab\x90{\xaa^\xadQ\xca\xbf\xd3\xbc\xd9\x93\xf0:D\xca\xd8v\x97\x08\xa8x\x9c-\n4\xd6e:,\n'\x01\x06\x00\x95O\x16\xafx\xe3\x94Y\rc\x7f\x10D\xcd\x9f\xaf<\xc7\xf4\xa2\x93f\xaa\r\x8c\xa3 \xe40\x0bZ\xfe\xb0xy\xbb\x12\x01\x00"  # noqa
        mock_tx = qrl_pb2.Transaction()
        mock_tx.ParseFromString(tx_pbdata_serialized_to_string)

        m_transfer_coins_resp = mock.MagicMock(name='a fake transferCoinsResp')
        m_transfer_coins_resp.extended_transaction_unsigned.tx = mock_tx
        m_push_transaction_resp = mock.MagicMock(name='a fake pushTransactionResp', error_code=3)

        attrs = {
            "name": "my fake stub",
            "TransferCoins.return_value": m_transfer_coins_resp,
            "PushTransaction.return_value": m_push_transaction_resp
        }
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = 'a fake qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        wallet = open_wallet()

        # Simplest use case
        result = self.runner.invoke(qrl_cli, [
            "tx_transfer",
            "--src=0",
            "--master=",
            "--dsts={}".format(qaddr_1),
            "--amounts=1",
            "--message_data=",
            "--fee=0",
            "--ots_key_index=0"
        ])
        self.assertEqual(result.exit_code, 0)
        print(result.output)
        self.assertIn('a fake pushTransactionResp', result.output.strip())

        # Should work with src=Qaddress as well
        result = self.runner.invoke(qrl_cli, [
            "tx_transfer",
            "--src={}".format(wallet["addresses"][0]["address"]),
            "--master=",
            "--dsts={}".format(qaddr_1),
            "--amounts=1",
            "--message_data=",
            "--fee=0",
            "--ots_key_index=0"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('a fake pushTransactionResp', result.output.strip())

        # Master should also work with a Qaddress.
        result = self.runner.invoke(qrl_cli, [
            "tx_transfer",
            "--src={}".format(wallet["addresses"][0]["address"]),
            "--master={}".format(qaddr_2),
            "--dsts={}".format(qaddr_1),
            "--amounts=1",
            "--message_data=",
            "--fee=0",
            "--ots_key_index=0"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('a fake pushTransactionResp', result.output.strip())

        # Multiple dsts should work too
        dsts = [qaddr_1, qaddr_2, qaddr_3]
        amounts = ["1", "2", "3"]
        result = self.runner.invoke(qrl_cli, [
            "tx_transfer",
            "--src=0",
            "--master=",
            "--dsts={}".format(" ".join(dsts)),
            "--amounts={}".format(" ".join(amounts)),
            "--message_data=",
            "--fee=0",
            "--ots_key_index=0"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('a fake pushTransactionResp', result.output.strip())

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_transfer_encrypted_wallet(self, mock_stub):
        tx_pbdata_serialized_to_string = b"\n\x02\\n\x1aC\x01\x02\x00\x80\x9dg/U\xb1N\xf2_\x0e~j%\xb2\x15\x05\xa7y\x19\x8f\xc0>\x05`\x90\xe3>\xaa\x9a(\xd3\xc7U\x91\xbab\x90{\xaa^\xadQ\xca\xbf\xd3\xbc\xd9\x93\xf0:D\xca\xd8v\x97\x08\xa8x\x9c-\n4\xd6e:,\n'\x01\x06\x00\x95O\x16\xafx\xe3\x94Y\rc\x7f\x10D\xcd\x9f\xaf<\xc7\xf4\xa2\x93f\xaa\r\x8c\xa3 \xe40\x0bZ\xfe\xb0xy\xbb\x12\x01\x00"  # noqa
        mock_tx = qrl_pb2.Transaction()
        mock_tx.ParseFromString(tx_pbdata_serialized_to_string)

        m_transferCoinsResp = mock.MagicMock(name='a fake transferCoinsResp')
        m_transferCoinsResp.extended_transaction_unsigned.tx = mock_tx

        m_pushTransactionResp = mock.MagicMock(name='a fake pushTransactionResp', error_code=3)

        attrs = {
            "name": "my fake stub",
            "TransferCoins.return_value": m_transferCoinsResp,
            "PushTransaction.return_value": m_pushTransactionResp
        }
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = 'a fake qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        # Simplest use case
        self.runner.invoke(qrl_cli, ["wallet_encrypt"], input='password\npassword\n')
        result = self.runner.invoke(qrl_cli, ["tx_transfer", "--src=0", "--master=", "--dsts={}".format(qaddr_1),
                                              "--amounts=1", "--message_data=", "--fee=0", "--ots_key_index=0"],
                                    input='password\n')
        self.assertEqual(result.exit_code, 0)
        self.assertIn('a fake pushTransactionResp', result.output.strip())

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_transfer_invalid_input(self, mock_stub):
        tx_pbdata_serialized_to_string = b"\n\x02\\n\x1aC\x01\x02\x00\x80\x9dg/U\xb1N\xf2_\x0e~j%\xb2\x15\x05\xa7y\x19\x8f\xc0>\x05`\x90\xe3>\xaa\x9a(\xd3\xc7U\x91\xbab\x90{\xaa^\xadQ\xca\xbf\xd3\xbc\xd9\x93\xf0:D\xca\xd8v\x97\x08\xa8x\x9c-\n4\xd6e:,\n'\x01\x06\x00\x95O\x16\xafx\xe3\x94Y\rc\x7f\x10D\xcd\x9f\xaf<\xc7\xf4\xa2\x93f\xaa\r\x8c\xa3 \xe40\x0bZ\xfe\xb0xy\xbb\x12\x01\x00"  # noqa
        mock_tx = qrl_pb2.Transaction()
        mock_tx.ParseFromString(tx_pbdata_serialized_to_string)

        m_transfer_coins_resp = mock.MagicMock(name='a fake transferCoinsResp')
        m_transfer_coins_resp.extended_transaction_unsigned.tx = mock_tx

        m_push_transaction_resp = mock.MagicMock(name='a fake pushTransactionResp', error_code=3)

        attrs = {
            "name": "my fake stub",
            "TransferCoins.return_value": m_transfer_coins_resp,
            "PushTransaction.return_value": m_push_transaction_resp
        }
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = 'a fake qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        # What if I use a ots_key_index larger than the wallet's tree height?
        result = self.runner.invoke(qrl_cli, [
            "tx_transfer",
            "--src=0",
            "--master=",
            "--dsts={}".format(qaddr_1),
            "--amounts=1",
            "--message_data=",
            "--fee=0",
            "--ots_key_index=16"], input='16')
        self.assertEqual(result.exit_code, 1)
        self.assertIn('OTS key index must be between 0 and 15', result.output.strip())

        # dsts and amounts with different lengths should fail
        dsts = [qaddr_1, qaddr_2, qaddr_3]
        amounts = ["1", "2"]
        result = self.runner.invoke(qrl_cli, [
            "tx_transfer",
            "--src=0",
            "--master=",
            "--dsts={}".format(" ".join(dsts)),
            "--amounts={}".format(" ".join(amounts)),
            "--message_data=",
            "--fee=0",
            "--ots_key_index=0"
        ])
        self.assertEqual(result.exit_code, 1)
        self.assertIn('dsts and amounts should be the same length', result.output.strip())

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_token(self, mock_stub):
        m_push_transaction_resp = mock.MagicMock(name='mock pushTransactionResp')
        m_push_transaction_resp.error_code = 'This was a test'

        attrs = {"name": "this should be qrl_pb2_grpc.PublicAPIStub(channel)",
                 "PushTransaction.return_value": m_push_transaction_resp}
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = "this should be qrl_pb2_grpc.PublicAPIStub"
        mock_stub.return_value = mock_stub_instance

        wallet = open_wallet()
        owner_address = wallet["addresses"][0]["address"]
        typed_in_input = '\n'.join([owner_address, '100']) + '\n'
        result = self.runner.invoke(qrl_cli, [
            "tx_token",
            "--src=0",
            "--master=",
            "--symbol=TST",
            "--name=TEST",
            "--owner={}".format(owner_address),
            "--decimals=1",
            "--fee=0",
            "--ots_key_index=0"
        ], input=typed_in_input)
        self.assertIn('This was a test', result.output)

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_token_invalid_input(self, mock_stub):
        m_push_transaction_resp = mock.MagicMock(name='mock pushTransactionResp')
        m_push_transaction_resp.error_code = 'This was a test'

        attrs = {"name": "this should be qrl_pb2_grpc.PublicAPIStub(channel)",
                 "PushTransaction.return_value": m_push_transaction_resp}
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = "this should be qrl_pb2_grpc.PublicAPIStub"
        mock_stub.return_value = mock_stub_instance

        wallet = open_wallet()
        owner_address = wallet["addresses"][0]["address"]
        typed_in_input = '\n'.join([owner_address, '100']) + '\n'

        # Weird token names and symbols shouldn't work
        result = self.runner.invoke(qrl_cli,
                                    [
                                        "tx_token",
                                        "--src=0",
                                        "--master=",
                                        "--symbol=thequickbrownfoxjumpsoverthelazydog",
                                        "--name=Seriouslyimgonnastarttalkingandneverendbecausethatsjusthowidothings "
                                        "can i have spaces in here what about |nny characters",
                                        "--owner={}".format(owner_address),
                                        "--decimals=1",
                                        "--fee=0",
                                        "--ots_key_index=0"
                                    ],
                                    input=typed_in_input
                                    )

        print(result.output)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('must be shorter than', result.output.strip())

        # An outrageous decimal precision shouldn't work either
        result = self.runner.invoke(qrl_cli,
                                    [
                                        "tx_token",
                                        "--src=0",
                                        "--master=",
                                        "--symbol=TST",
                                        "--name=TEST",
                                        "--owner={}".format(owner_address),
                                        "--decimals=1000",
                                        "--fee=0",
                                        "--ots_key_index=0"
                                    ],
                                    input=typed_in_input
                                    )

        print(result.output)
        print(result.exc_info)
        self.assertEqual(result.exit_code, 1)

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_transfertoken(self, mock_stub):
        m_push_transaction_resp = mock.MagicMock(name='mock pushTransactionResp')
        m_push_transaction_resp.error_code = 'This was a test'

        attrs = {"name": "this should be qrl_pb2_grpc.PublicAPIStub(channel)",
                 "PushTransaction.return_value": m_push_transaction_resp}
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = "this should be qrl_pb2_grpc.PublicAPIStub"
        mock_stub.return_value = mock_stub_instance

        txhash = '267d9c6e192c78b192b6e835411d30f7cb605ffe9632d668489c579e4230f3c6'  # from sample tx_token run

        result = self.runner.invoke(qrl_cli,
                                    [
                                        "tx_transfertoken",
                                        "--src=0",
                                        "--master=",
                                        "--token_txhash={}".format(txhash),
                                        "--dsts={}".format(qaddr_1),
                                        "--amounts=10",
                                        "--decimals=10",
                                        "--fee=0",
                                        "--ots_key_index=0"
                                    ])

        print(result.output)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output.strip(), 'This was a test')

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_tx_transfertoken_invalid_input(self, mock_stub):
        m_push_transaction_resp = mock.MagicMock(name='mock pushTransactionResp')
        m_push_transaction_resp.error_code = 'This was a test'

        attrs = {"name": "this should be qrl_pb2_grpc.PublicAPIStub(channel)",
                 "PushTransaction.return_value": m_push_transaction_resp}
        mock_stub_instance = mock.MagicMock(**attrs)

        mock_stub.name = "this should be qrl_pb2_grpc.PublicAPIStub"
        mock_stub.return_value = mock_stub_instance

        txhash = '267d9c6e192c78b192b6e835411d30f7cb605ffe9632d668489c579e4230f3c6'  # from sample tx_token run

        # Invalid txhash shouldn't work.
        result = self.runner.invoke(qrl_cli,
                                    [
                                        "tx_transfertoken",
                                        "--src=0",
                                        "--master=",
                                        "--token_txhash={}".format(txhash[3:]),
                                        "--dsts={}".format(qaddr_1),
                                        "--amounts=10",
                                        "--decimals=10",
                                        "--fee=0",
                                        "--ots_key_index=0"],
                                    )

        print(result.output)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('hex string is expected to have an even number of characters', result.output.strip())

        # If decimals is different from the original token_txhash definition, it shouldn't work either.
        # But maybe this is for integration tests.
        # result = self.runner.invoke(qrl_cli,
        #                             ["tx_transfertoken", "--src=0", "--master=",
        #                              "--token_txhash={}".format(txhash), "--dsts={}".format(qaddr_1), "--amounts=10",
        #                              "--decimals=999", "--fee=0", "--ots_key_index=1"],
        #                             )
        # self.assertEqual(result.exit_code, 1)
        # self.assertNotIn('This was a test', result.output.strip())

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_token_list(self, mock_stub):
        m_address_state_resp = mock.MagicMock(name='this should be the addressStateResp')
        m_address_state_resp.state.tokens = {'aabb00': 10, 'ccbb11': 100}
        transaction = mock.MagicMock()
        transaction.token = mock.MagicMock()
        transaction.token.name = b"NAME"
        transaction.token.symbol = b"SYM"
        tx_extended = mock.MagicMock(tx=transaction)
        get_object_resp = mock.MagicMock(transaction=tx_extended)

        mock_stub_instance = mock.MagicMock(name='this should be qrl_pb2_grpc.PublicAPIStub(channel)')
        mock_stub_instance.GetAddressState.return_value = m_address_state_resp
        mock_stub_instance.GetObject.return_value = get_object_resp

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        result = self.runner.invoke(qrl_cli, ["token_list", "--owner={}".format(qaddr_1)])

        self.assertIn('Hash: {}\nSymbol: {}\nName: {}\nBalance: 10'.format('aabb00',
                                                                           transaction.token.symbol.decode(),
                                                                           transaction.token.name.decode()), result.output)
        self.assertIn('Hash: {}\nSymbol: {}\nName: {}\nBalance: 100'.format('ccbb11',
                                                                            transaction.token.symbol.decode(),
                                                                            transaction.token.name.decode()), result.output)

    @mock.patch('qrl.cli.qrl_pb2_grpc.PublicAPIStub', autospec=True)
    def test_token_list_invalid_input(self, mock_stub):
        m_address_state_resp = mock.MagicMock(name='this should be the addressStateResp')
        m_address_state_resp.state.tokens = {qaddr_1: 10, qaddr_2: 100}

        mock_stub_instance = mock.MagicMock(name='this should be qrl_pb2_grpc.PublicAPIStub(channel)')
        mock_stub_instance.GetAddressState.return_value = m_address_state_resp

        mock_stub.name = 'this should be qrl_pb2_grpc.PublicAPIStub'
        mock_stub.return_value = mock_stub_instance

        # Malformed Qaddress should fail!
        result = self.runner.invoke(qrl_cli, ["token_list", "--owner={}".format(qaddr_1[:-1])])

        self.assertEqual(1, result.exit_code)
        self.assertIn('hex string is expected to have an even number of characters', result.output.strip())
