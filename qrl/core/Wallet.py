# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
from collections import namedtuple
from typing import List, Optional

import simplejson
from pyqrllib.pyqrllib import mnemonic2bin, bin2hstr

from qrl.core import config
from qrl.core.misc import logger
from qrl.crypto.xmss import XMSS

AddressItem = namedtuple('AddressItem',
                         'address hexseed mnemonic height hashFunction signatureType index encrypted')


class Wallet:
    # TODO: Extremely simple persistance. Upgrade to protobuf / encrypt / etc.
    # TODO: Allow for wallets to be removed / modified?
    # TODO: Consider error handling in the new version
    def __init__(self, valid_or_create=True):
        self._addresses = self._read_wallet(self.wallet_path)
        if self._addresses is None or len(self._addresses) == 0:
            if valid_or_create:
                self._addresses = [self.get_new_address()]
            self.save_wallet(self.wallet_path)

    @property
    def wallet_path(self) -> str:
        config.create_path(config.user.wallet_dir)
        return os.path.join(config.user.wallet_dir,
                            config.dev.wallet_dat_filename)

    @property
    def addresses(self) -> List[bytes]:
        return [bytes(xmss.address) for xmss in self._addresses]

    def get_xmss_by_index(self, index) -> Optional[XMSS]:
        if index < len(self._addresses):
            return self._addresses[index]
        return None

    def get_xmss_by_address(self, addr) -> Optional[XMSS]:
        for xmss in self._addresses:
            if addr == xmss.address:
                return xmss
        return None

    @staticmethod
    def _get_address_item(xmss: XMSS) -> AddressItem:
        return AddressItem(
            address=xmss.address,
            hexseed=xmss.hexseed,
            mnemonic=xmss.mnemonic,
            height=xmss.height,
            hashFunction=None,
            signatureType=None,
            index=xmss.ots_index,
            encrypted=False
        )

    @staticmethod
    def _get_xmss_from_dict(address_dict) -> Optional[XMSS]:
        extended_seed = mnemonic2bin(address_dict['mnemonic'].strip())
        tmp_xmss = XMSS.from_extended_seed(extended_seed)
        tmp_xmss.set_ots_index(address_dict['index'])

        if address_dict['address'] != 'Q' + bin2hstr(tmp_xmss.address):
            raise Exception("Mnemonic and address do not match.")

        return tmp_xmss

    def save_wallet(self, filename):
        data = [self._get_address_item(addr_item) for addr_item in self._addresses]
        with open(filename, "wb") as outfile:
            outfile.write(simplejson.dumps(data))

    def _read_wallet(self, filename) -> List[XMSS]:
        answer = []

        try:
            with open(filename, "rb") as infile:
                wallet_store = simplejson.loads(infile.read())

                for address_item in wallet_store:
                    tmp_xmss = self._get_xmss_from_dict(address_item)
                    answer.append(tmp_xmss)

        except Exception as e:
            logger.warning("It was not possible to open the wallet: %s", e)

        return answer

    def append_xmss(self, xmss):
        if xmss:
            self._addresses.append(xmss)
            self.save_wallet(self.wallet_path)

    def get_num_signatures_by_index(self, index) -> int:
        xmss = self.get_xmss_by_index(index)
        if xmss is not None:
            return xmss.remaining_signatures()
        return 0

    def get_num_signatures_by_addr(self, address_to_check):
        xmss = self.get_xmss_by_address(address_to_check)
        if xmss is not None:
            return xmss.remaining_signatures()
        return 0
