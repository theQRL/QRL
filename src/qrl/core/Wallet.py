# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import functools
import os
from collections import namedtuple
from typing import List, Optional

import simplejson
from pyqrllib.pyqrllib import mnemonic2bin, bin2hstr, hstr2bin

from qrl.core import config
from qrl.core.misc import logger
from qrl.crypto.AESHelper import AESHelper
from qrl.crypto.xmss import XMSS

AddressItem = namedtuple('AddressItem',
                         'address pk hexseed mnemonic height hashFunction signatureType index encrypted')


class Wallet:
    def __init__(self, wallet_path=None):
        if wallet_path is None:
            wallet_path = self.get_default_wallet_path()

        self.wallet_path = wallet_path
        self._address_items = self._read_wallet(self.wallet_path)

    @staticmethod
    def get_default_wallet_path() -> str:
        config.create_path(config.user.wallet_dir)
        return os.path.join(config.user.wallet_dir,
                            config.dev.wallet_dat_filename)

    @property
    def address_items(self) -> List[AddressItem]:
        """
        Returns all address items in the wallet
        :return:
        """
        return self._address_items

    @property
    def addresses(self) -> List[bytes]:
        """
        Returns all address items in the wallet
        :return:
        """
        return [bytes(hstr2bin(item.address[1:])) for item in self._address_items]

    @functools.lru_cache(maxsize=20)
    def get_xmss_by_index(self, idx) -> Optional[XMSS]:
        """
        Generates an XMSS tree based on the information contained in the wallet
        :param idx: The index of the address item
        :return: An XMSS tree object
        """
        if idx >= len(self._address_items):
            return None

        item = self._address_items[idx]
        extended_seed = mnemonic2bin(item.mnemonic.strip())
        tmp_xmss = XMSS.from_extended_seed(extended_seed)
        tmp_xmss.set_ots_index(item.index)

        if item.address != 'Q' + bin2hstr(tmp_xmss.address):
            raise Exception("Mnemonic and address do not match.")

        if item.hexseed != tmp_xmss.hexseed:
            raise Exception("hexseed does not match.")

        if item.mnemonic != tmp_xmss.mnemonic:
            raise Exception("mnemonic does not match.")

        if item.height != tmp_xmss.height:
            raise Exception("height does not match.")

        return tmp_xmss

    @staticmethod
    def _get_Qaddress(addr: bytes) -> str:
        """
        Gets an address in QHex format
        :param addr:
        :return:
        """
        return 'Q' + bin2hstr(addr)

    @staticmethod
    def _get_address_item_from_xmss(xmss: XMSS) -> AddressItem:
        return AddressItem(
            address=Wallet._get_Qaddress(xmss.address),
            pk=None,
            hexseed=xmss.hexseed,
            mnemonic=xmss.mnemonic,
            height=xmss.height,
            hashFunction=None,
            signatureType=None,
            index=xmss.ots_index,
            encrypted=False
        )

    @staticmethod
    def _get_address_item_from_json(addr_json: dict) -> AddressItem:
        return AddressItem(**addr_json)

    def get_xmss_by_address(self, search_addr) -> Optional[XMSS]:
        search_addr_str = self._get_Qaddress(search_addr)
        for idx, item in enumerate(self._address_items):
            if item.address == search_addr_str:
                return self.get_xmss_by_index(idx)
        return None

    def verify_wallet(self):
        """
        Confirms that json address data is correct and valid.
        In order to verify, it needs to create XMSS trees, so the operation
        is time consuming
        :return: True if valid
        """
        return True

    def _read_wallet(self, filename) -> List[AddressItem]:
        answer = []

        if not os.path.isfile(filename):
            return answer

        try:
            with open(filename, "rb") as infile:
                data = simplejson.loads(infile.read())
                answer = [self._get_address_item_from_json(d) for d in data]

        except Exception as e:
            logger.warning("ReadWallet: %s", e)

        return answer

    def save_wallet(self, filename):
        with open(filename, "wb") as outfile:
            data_out = simplejson.dumps(self._address_items).encode('ascii')
            outfile.write(data_out)

    def decrypt_item(self, index: int, key: str):
        if index < len(self._address_items):
            cipher = AESHelper(key)
            tmp = self._address_items[index]._asdict()  # noqa
            tmp['address'] = cipher.decrypt(tmp['address']).decode()
            tmp['hexseed'] = cipher.decrypt(tmp['hexseed']).decode()
            tmp['mnemonic'] = cipher.decrypt(tmp['mnemonic']).decode()
            tmp['encrypted'] = False
            self._address_items[index] = AddressItem(**tmp)

    def encrypt_item(self, index: int, key: str):
        if index < len(self._address_items):
            cipher = AESHelper(key)
            tmp = self._address_items[index]._asdict()  # noqa
            tmp['address'] = cipher.encrypt(tmp['address'].encode())
            tmp['hexseed'] = cipher.encrypt(tmp['hexseed'].encode())
            tmp['mnemonic'] = cipher.encrypt(tmp['mnemonic'].encode())
            tmp['encrypted'] = True
            self._address_items[index] = AddressItem(**tmp)

    def decrypt(self, key: str):
        for i in range(len(self._address_items)):
            self.decrypt_item(i, key)

    def encrypt(self, key: str):
        for i in range(len(self._address_items)):
            self.encrypt_item(i, key)

    def save(self):
        self.save_wallet(self.wallet_path)

    def load(self):
        self._read_wallet(self.wallet_path)

    def append_xmss(self, xmss):
        if xmss:
            tmp_item = self._get_address_item_from_xmss(xmss)
            self._address_items.append(tmp_item)
            self.save_wallet(self.wallet_path)

    def add_new_address(self, height):
        tmp_xmss = XMSS.from_height(height)
        self.append_xmss(tmp_xmss)
        return tmp_xmss
