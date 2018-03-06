# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from unittest import TestCase

from qrl.core.misc import logger

logger.initialize_default()


class TestCLI(TestCase):
    def __init__(self, *args, **kwargs):
        super(TestCLI, self).__init__(*args, **kwargs)

    # def test_print_addresses(self):
    #     with set_wallet_dir("test_wallet"):
    #         config.user.wallet_dir = ctx.obj.wallet_dir
    #         wallet = Wallet()
    #         _print_addresses(ctx, wallet.address_items, config.user.wallet_dir)
