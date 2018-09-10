# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import functools
import os
from typing import List, Optional

import simplejson
from pyqrllib.pyqrllib import mnemonic2bin, bin2hstr, hstr2bin

from qrl.core import config
from qrl.core.misc import logger
from qrl.crypto.AESHelper import AESHelper
from qrl.crypto.xmss import XMSS
from qrl.core.AddressHelper import hex_to_b32address


class AddressItem:
    def __init__(self):
        self.qaddress = None
        self.b32address = None
        self.pk = None
        self.hexseed = None
        self.mnemonic = None
        self.height = None
        self.hashFunction = None
        self.signatureType = None
        self.index = None
        self.encrypted = None

        self.xmss = None

    def __eq__(self, other):
        result = (self.qaddress == other.qaddress and
                  self.b32address == other.b32address and
                  self.hexseed == other.hexseed and
                  self.mnemonic == other.mnemonic and
                  self.height == other.height and
                  self.hashFunction == other.hashFunction and
                  self.signatureType == other.signatureType and
                  self.index == other.index and
                  self.encrypted == other.encrypted
                  )
        return result

    def set_xmss(self, xmss):
        self.xmss = xmss

        self.qaddress = xmss.qaddress
        self.b32address = xmss.b32address
        self.pk = bin2hstr(xmss.pk)
        self.hexseed = xmss.hexseed
        self.mnemonic = xmss.mnemonic
        self.height = xmss.height
        self.hashFunction = xmss.hash_function
        self.signatureType = xmss.signature_type
        self.index = xmss.ots_index

        self.encrypted = False

    def serialize(self):
        serialized = {
            "address": self.qaddress,
            "address_b32": self.b32address,
            "pk": self.pk,
            "hexseed": self.hexseed,
            "mnemonic": self.mnemonic,
            "height": self.height,
            "hashFunction": self.hashFunction,
            "signatureType": self.signatureType,
            "index": self.index,
        }
        return serialized

    def deserialize(self, addr_json: dict, encrypted: bool):
        """
        webwallet uses 'address', but the node uses 'qaddress'. Translate address -> qaddress.
        Since version 1, encrypted = True/False is at the Wallet level. Thus without inspecting the hexseed/mnemonic,
        AddressItem cannot know itself if it is encrypted. Therefore the Wallet has to tell the AddressItem that it is
        encrypted.
        :param addr_json:
        :param encrypted:
        :return:
        """
        self.qaddress = addr_json.get("address")
        self.b32address = addr_json.get("address_b32", hex_to_b32address(self.qaddress))
        self.pk = addr_json.get("pk")
        self.hexseed = addr_json.get("hexseed")
        self.mnemonic = addr_json.get("mnemonic")
        self.height = addr_json.get("height")
        self.hashFunction = addr_json.get("hashFunction")
        self.signatureType = addr_json.get("signatureType")
        self.index = addr_json.get("index")

        self.encrypted = encrypted

    def deserialize_ver0(self, addr_json: dict):
        """
        webwallet uses 'address', but the node uses 'qaddress'. Translate address -> qaddress.
        :param addr_json:
        :return:
        """
        self.qaddress = addr_json.get("address")
        try:
            self.b32address = hex_to_b32address(self.qaddress)
        except ValueError:
            pass  # qaddress could be encrypted in version 0. Move on.
        self.pk = addr_json.get("pk")
        self.hexseed = addr_json.get("hexseed")
        self.mnemonic = addr_json.get("mnemonic")
        self.height = addr_json.get("height")
        self.hashFunction = addr_json.get("hashFunction")
        self.signatureType = addr_json.get("signatureType")
        self.index = addr_json.get("index")
        self.encrypted = addr_json.get("encrypted")

    def encrypt(self, key: str):
        cipher = AESHelper(key)
        self.hexseed = cipher.encrypt(self.hexseed.encode())
        self.mnemonic = cipher.encrypt(self.mnemonic.encode())
        self.encrypted = True

    def decrypt(self, key: str):
        cipher = AESHelper(key)
        self.hexseed = cipher.decrypt(self.hexseed).decode()
        self.mnemonic = cipher.decrypt(self.mnemonic).decode()
        self.encrypted = False

    def decrypt_ver0(self, key: str):
        cipher = AESHelper(key)
        self.qaddress = cipher.decrypt(self.qaddress).decode()
        self.hexseed = cipher.decrypt(self.hexseed).decode()
        self.mnemonic = cipher.decrypt(self.mnemonic).decode()
        self.encrypted = False

        self.b32address = hex_to_b32address(self.qaddress)


class WalletException(Exception):
    pass


class WalletEncryptionError(WalletException):
    pass


class WalletDecryptionError(WalletException):
    pass


class WalletVersionError(WalletException):
    pass


class Wallet:
    def __init__(self, wallet_path=None):
        if wallet_path is None:
            wallet_path = self.get_default_wallet_path()

        self.wallet_path = wallet_path
        self._address_items = []
        self.version = 1

        self.load()

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
        return [bytes(hstr2bin(item.qaddress[1:])) for item in self._address_items]

    @property
    def encrypted(self) -> bool:
        if len(self.address_items) == 0:
            return False
        return all([item.encrypted for item in self.address_items])

    @property
    def encrypted_partially(self) -> bool:
        # FIXME: slow, makes 2 passes over address_items.
        return any([item.encrypted for item in self.address_items]) and not self.encrypted

    @functools.lru_cache(maxsize=20)
    def get_xmss_by_index(self, idx, passphrase=None) -> Optional[XMSS]:
        """
        Generates an XMSS tree based on the information contained in the wallet
        :param idx: The index of the address item
        :param passphrase: passphrase to decrypt
        :return: An XMSS tree object
        """
        if passphrase:
            self.decrypt_item(idx, passphrase)

        xmss = self._get_xmss_by_index_no_cache(idx)

        if passphrase:
            self.encrypt_item(idx, passphrase)

        return xmss

    def is_encrypted(self) -> bool:
        if len(self.address_items) == 0:
            return False

        return self.address_items[0].encrypted

    def wallet_info(self):
        """
        Provides Wallet Info
        :return:
        """

        return self.version, len(self._address_items), self.encrypted

    def _get_xmss_by_index_no_cache(self, idx) -> Optional[XMSS]:
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

        if item.qaddress != 'Q' + bin2hstr(tmp_xmss.address):
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

    def get_address_item(self, qaddress) -> [int, AddressItem]:
        for idx, item in enumerate(self._address_items):
            if item.qaddress == qaddress:
                return idx, item
        return -1, None

    def get_xmss_by_address(self, search_addr) -> Optional[XMSS]:
        search_addr_str = self._get_Qaddress(search_addr)
        return self.get_xmss_by_qaddress(search_addr_str)

    def get_xmss_by_qaddress(self, search_addr_str, passphrase: str = None) -> Optional[XMSS]:
        idx, _ = self.get_address_item(search_addr_str)

        if idx == -1:
            return None

        return self.get_xmss_by_index(idx, passphrase)

    def set_ots_index(self, i, ots_index):
        self._address_items[i].index = ots_index
        self.save()

    def verify_wallet(self):
        """
        Confirms that json address data is correct and valid.
        In order to verify, it needs to create XMSS trees, so the operation
        is time consuming
        :return: True if valid
        """
        num_items = len(self._address_items)

        if not self.encrypted:
            try:
                for i in range(num_items):
                    self._get_xmss_by_index_no_cache(i)
            except Exception as e:
                logger.warning(e)
                return False

        return True

    def _read_wallet_ver0(self, filename) -> None:
        def get_address_item_from_json(addr_json: dict) -> AddressItem:
            address_item = AddressItem()
            address_item.deserialize_ver0(addr_json)
            return address_item

        try:
            with open(filename, "rb") as infile:
                data = simplejson.loads(infile.read())
                answer = [get_address_item_from_json(d) for d in data]
            self._address_items = answer
            self.version = 0
        except FileNotFoundError:
            return

    def _read_wallet_ver1(self, filename) -> None:
        def get_address_item_from_json(addr_json: dict, encrypted: bool) -> AddressItem:
            address_item = AddressItem()
            address_item.deserialize(addr_json, encrypted)
            return address_item

        try:
            with open(filename, "rb") as infile:
                data = simplejson.loads(infile.read())
                answer = [get_address_item_from_json(d, data["encrypted"]) for d in data["addresses"]]
            self._address_items = answer
            self.version = 1
        except FileNotFoundError:
            return

    def save_wallet(self, filename):
        if not self.verify_wallet():
            raise WalletException("Could not be saved. Invalid wallet.")

        with open(filename, "wb") as outfile:
            address_items_asdict = [a.serialize() for a in self._address_items]

            output = {
                "addresses": address_items_asdict,
                "encrypted": self.encrypted,
                "version": 1
            }
            data_out = simplejson.dumps(output).encode('ascii')
            outfile.write(data_out)

    def decrypt(self, password: str, first_address_only: bool = False):
        if self.encrypted_partially:
            raise WalletEncryptionError("Some addresses are already decrypted. Please re-encrypt all addresses before"
                                        "running decrypt().")
        elif not self.encrypted:
            raise WalletEncryptionError("Wallet is already unencrypted.")

        try:
            for address_item in self._address_items:
                if self.version == 0:
                    address_item.decrypt_ver0(password)
                elif self.version == 1:
                    address_item.decrypt(password)
                else:
                    raise WalletVersionError("Wallet.decrypt() can only decrypt wallet.jsons of version 0/1")

                if first_address_only:
                    return
        except Exception as e:
            raise WalletDecryptionError("Error during decryption. Likely due to invalid password: {}".format(str(e)))

        if not self.verify_wallet():
            raise WalletDecryptionError("Decrypted wallet is not valid. Likely due to invalid password")

    def encrypt(self, key: str):
        if self.encrypted_partially:
            raise WalletEncryptionError("Please decrypt all addresses before adding a new one to the wallet."
                                        "This is to ensure they are all encrypted with the same key.")
        elif self.encrypted:
            raise WalletEncryptionError("Wallet is already encrypted.")

        for address_item in self._address_items:
            address_item.encrypt(key)

    def save(self):
        if self.version == 0:
            raise WalletVersionError("Your wallet.json is version 0. Saving will transform it to version 1."
                                     "Please decrypt your wallet before proceeding.")

        if self.encrypted_partially:
            raise WalletEncryptionError("Not all addresses are encrypted! Please ensure everything is "
                                        "decrypted/encrypted before saving it.")

        self.save_wallet(self.wallet_path)

    def load(self):
        try:
            self._read_wallet_ver1(self.wallet_path)
        except TypeError:
            logger.info("ReadWallet: reading ver1 wallet failed, this must be an old wallet")
            self._read_wallet_ver0(self.wallet_path)

    def append_xmss(self, xmss):
        address_item = AddressItem()
        address_item.set_xmss(xmss)
        self._address_items.append(address_item)

    def add_new_address(self, height, hash_function="shake128", force=False):
        if not force:
            if self.encrypted or self.encrypted_partially:
                raise WalletEncryptionError("Please decrypt all addresses in this wallet before adding a new address!")

        tmp_xmss = XMSS.from_height(height, hash_function)

        self.append_xmss(tmp_xmss)
        return tmp_xmss

    def remove(self, addr) -> bool:
        for item in self._address_items:
            if item.qaddress == addr:
                try:
                    self._address_items.remove(item)
                    self.save_wallet(self.wallet_path)
                    return True
                except ValueError:
                    logger.warning("Could not remove address from wallet")
        return False
