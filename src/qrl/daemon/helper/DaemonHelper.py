# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import functools
import os
from typing import List, Optional

import simplejson
from pyqrllib.pyqrllib import mnemonic2bin, bin2hstr, hstr2bin

from qrl.core import config
from qrl.core.AddressHelper import hex_to_b32address, hex_to_rawaddress, any_to_rawaddress
from qrl.core.misc import logger
from qrl.crypto.AESHelper import AESHelper
from qrl.crypto.xmss import XMSS


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
        self.slaves = []

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
                  self.encrypted == other.encrypted and
                  self.slaves == other.slaves
                  )
        return result

    @property
    def address_raw(self):
        return hex_to_rawaddress(self.qaddress)

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

    def generate_xmss(self):
        """
        Generates an XMSS tree based on the information contained in the AddressItem
        """
        extended_seed = mnemonic2bin(self.mnemonic.strip())
        tmp_xmss = XMSS.from_extended_seed(extended_seed)
        tmp_xmss.set_ots_index(self.index)

        if self.qaddress != 'Q' + bin2hstr(tmp_xmss.address):
            raise Exception("Mnemonic and address do not match.")

        if self.hexseed != tmp_xmss.hexseed:
            raise Exception("hexseed does not match.")

        if self.mnemonic != tmp_xmss.mnemonic:
            raise Exception("mnemonic does not match.")

        if self.height != tmp_xmss.height:
            raise Exception("height does not match.")

        self.set_xmss(tmp_xmss)

    def serialize(self):
        slaves_serialized = []
        for slave_group in self.slaves:
            g = []
            for slave in slave_group:
                g.append(slave.serialize())
            slaves_serialized.append(g)

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
            "slaves": slaves_serialized,
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

        self.slaves = []
        slaves_serialized = addr_json.get("slaves")
        for slave_group in slaves_serialized:
            g = []
            for slave in slave_group:
                a = AddressItem()
                a.deserialize(slave, encrypted)
                g.append(a)
            self.slaves.append(g)

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

        for slave_group in self.slaves:
            for slave in slave_group:
                slave.encrypt(key)

        self.encrypted = True

    def decrypt(self, key: str):
        cipher = AESHelper(key)
        self.hexseed = cipher.decrypt(self.hexseed).decode()
        self.mnemonic = cipher.decrypt(self.mnemonic).decode()

        for slave_group in self.slaves:
            for slave in slave_group:
                slave.decrypt(key)

        self.encrypted = False

    def decrypt_ver0(self, key: str):
        cipher = AESHelper(key)
        self.qaddress = cipher.decrypt(self.qaddress).decode()
        self.hexseed = cipher.decrypt(self.hexseed).decode()
        self.mnemonic = cipher.decrypt(self.mnemonic).decode()
        self.encrypted = False

        self.b32address = hex_to_b32address(self.qaddress)

    def set_ots_index(self, index):
        self.index = index

        """
        FIXME: AddressItem.index may be different from XMSS.index Why? Read on
        Suppose height = 8. AddressItem.index = 256 means that all indexes are used already, while XMSS.index remains
        at 255.
        Basically AddressItem should be refactored in the future to handle more complex management surrounding XMSS.
        """
        if self.xmss and (index < 2**self.height):
            self.xmss.set_ots_index(index)


UNRESERVED_OTS_INDEX_START = 5


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
    def get_xmss_by_index(self, idx) -> Optional[XMSS]:
        """
        Tells the underlying AddressItem to generate the XMSS tree (it should have enough info at this point)
        The AddressItem needs to be decrypted first.
        :return: An XMSS tree object
        """
        self.address_items[idx].generate_xmss()
        return self.address_items[idx].xmss

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

    def get_address_item(self, address_str: str) -> [int, AddressItem]:
        address_raw = any_to_rawaddress(address_str)
        for idx, item in enumerate(self._address_items):
            if item.address_raw == address_raw:
                return idx, item
        return -1, None

    def get_xmss_by_address_raw(self, address_raw: bytes) -> Optional[XMSS]:
        for idx, item in enumerate(self._address_items):
            if item.address_raw == address_raw:
                return self.get_xmss_by_index(idx)

        return None

    def get_xmss_by_address_any(self, address_str) -> Optional[XMSS]:
        idx, _ = self.get_address_item(address_str)

        if idx == -1:
            return None

        return self.get_xmss_by_index(idx)

    def set_ots_index(self, i, ots_index):
        self._address_items[i].index = ots_index
        self.save()

    def set_slave_ots_index(self, index, group_index, slave_index, ots_index):
        slave = self._address_items[index].slaves[group_index][slave_index]
        slave.set_ots_index(ots_index)
        self.save()

    def verify_wallet(self):
        """
        Confirms that json address data is correct and valid.
        In order to verify, it needs to create XMSS trees, so the operation
        is time consuming
        :return: True if valid
        """
        if not self.encrypted:
            for address_item in self.address_items:
                try:
                    address_item.generate_xmss()
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

    def append_slave(self, slaves: list, passphrase: str, index=-1):
        if passphrase:
            for s in slaves:
                s.encrypt(passphrase)
        self._address_items[index].slaves.append(slaves)

    def add_new_address(self, height, hash_function="shake128", force=False):
        if not force:
            if self.encrypted or self.encrypted_partially:
                raise WalletEncryptionError("Please decrypt all addresses in this wallet before adding a new address!")

        tmp_xmss = XMSS.from_height(height, hash_function)

        self.append_xmss(tmp_xmss)
        return tmp_xmss

    def add_slave(self, index, height, number_of_slaves=1, passphrase: str = None, hash_function="shake128",
                  force=False):
        if not force:
            if self.encrypted or self.encrypted_partially:
                raise WalletEncryptionError("Please decrypt all addresses in this wallet before adding a new address!")

        slaves = []

        for i in range(number_of_slaves):
            tmp_xmss = XMSS.from_height(height, hash_function)
            if i == number_of_slaves - 1:  # The last slave in every slave group should have some reserved ots indexes.
                tmp_xmss.set_ots_index(UNRESERVED_OTS_INDEX_START)

            address_item = AddressItem()
            address_item.set_xmss(tmp_xmss)
            slaves.append(address_item)

        self.append_slave(slaves, passphrase, index)
        return slaves

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
