import decimal
import os

from decimal import Decimal

import time

from qrl.core import config, logger
from qrl.core.Transaction import TransferTransaction
from qrl.core.state import State
from qrl.generated import qrl_pb2


# FIXME: This will soon move to core. Split/group functionality
class QRLNode:
    def __init__(self, db_state: State):
        self.start_time = time.time()

        self.peer_addresses = []
        self.peers_path = os.path.join(config.user.data_path, config.dev.peers_filename)
        self._load_peer_addresses()

        self.db_state = db_state
        self._chain = None  # FIXME: REMOVE. This is temporary
        self._p2pfactory = None  # FIXME: REMOVE. This is temporary

    @property
    def version(self):
        # FIXME: Move to __version__ coming from pip
        return config.dev.version_number

    @property
    def state(self):
        # FIXME
        return self._p2pfactory.nodeState.state.value

    @property
    def num_connections(self):
        # FIXME
        return self._p2pfactory.connections

    @property
    def num_known_peers(self):
        # FIXME
        return len(self.peer_addresses)

    @property
    def uptime(self):
        return int(time.time() - self.start_time)

    @property
    def block_height(self):
        # FIXME
        return self._chain.m_blockheight()

    @property
    def staking(self):
        return self._p2pfactory.stake

    # FIXME: REMOVE. This is temporary
    def set_chain(self, chain):
        self._chain = chain

    # FIXME: REMOVE. This is temporary
    def set_p2pfactory(self, p2pfactory):
        self._p2pfactory = p2pfactory

    def _load_peer_addresses(self) -> None:
        try:
            if os.path.isfile(self.peers_path):
                logger.info('Opening peers.qrl')
                with open(self.peers_path, 'rb') as infile:
                    known_peers = qrl_pb2.KnownPeers()
                    known_peers.ParseFromString(infile.read())
                    self.peer_addresses = [peer.ip for peer in known_peers.peers]
                    return
        except Exception as e:
            logger.warning("Error loading peers")
            logger.exception(e)

        logger.info('Creating peers.qrl')
        # Ensure the data path exists
        config.create_path(config.user.data_path)
        self.update_peer_addresses(config.user.peer_list)

        logger.info('Known Peers: %s', self.peer_addresses)

    def update_peer_addresses(self, peer_addresses) -> None:
        # FIXME: Probably will be refactored
        self.peer_addresses = peer_addresses
        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.peer_addresses])
        with open(self.peers_path, "wb") as outfile:
            outfile.write(known_peers.SerializeToString())

    def get_address_state(self, address: bytes) -> qrl_pb2.AddressState:
        # FIXME: Refactor. Define concerns, etc.
        # FIXME: Unnecessary double conversion

        # TODO: Validate address format
        if address[0] != b'Q':
            return None

        nonce, balance, pubhash_list = self.db_state.get_address(address)
        transactions = []

        address_state = qrl_pb2.AddressState(address=address,
                                             balance=balance,
                                             nonce=nonce,
                                             transactions=transactions)

        return address_state

    def get_dec_amount(self, str_amount_arg: str) -> Decimal:
        # FIXME: Concentrating logic into a single point. Fix this, make type safe to avoid confusion. Quantity formats should be always clear
        # FIXME: Review. This is just relocated code. It looks odd
        # FIXME: Antipattern. Magic number.
        # FIXME: Validate string, etc.
        return decimal.Decimal(decimal.Decimal(str_amount_arg) * 100000000).quantize(decimal.Decimal('1'),
                                                                                     rounding=decimal.ROUND_HALF_UP)

    def get_wallet_absolute(self, addr_or_index):
        # FIXME: Refactor. Define concerns, etc. Validation vs logic
        # FIXME: It is possible to receive integers instead of strings....

        if addr_or_index == b'':
            raise ValueError("address is empty")

        if addr_or_index.isdigit():
            # FIXME: The whole idea of accepting relative (index based) wallets internally is flawed.
            # There is a risk of confusing things. Relative should be a feature of UIs

            num_wallets = len(self._chain.wallet.address_bundle)
            addr_idx = int(addr_or_index)
            if 0 <= addr_idx < num_wallets:
                return self._chain.wallet.address_bundle[addr_idx].address
            else:
                raise ValueError("invalid address index")

        if addr_or_index[0] != ord('Q'):
            raise ValueError("Invalid address")

        return addr_or_index

    def validate_amount(self, amount_str: str) -> bool:
        # FIXME: Refactored code. Review Decimal usage all over the code
        amount = Decimal(amount_str)
        return True

    def _find_xmss(self, key_addr: bytes):
        # FIXME: Move down the wallet management
        for addr in self._chain.wallet.address_bundle:
            if addr.address == key_addr:
                return addr.xmss
        return None

    # FIXME: Rename this appropriately
    def transfer_coins(self, addr_from: bytes, addr_to: bytes, amount: int, fee: int = 0):
        block_chain_buffer = self._chain.block_chain_buffer
        stake_validators_list = block_chain_buffer.get_stake_validators_list(block_chain_buffer.height() + 1)

        xmss_from = self._find_xmss(addr_from)

        if addr_from in stake_validators_list.sv_list or addr_from in stake_validators_list.future_stake_addresses:
            raise LookupError("Source address is a Stake Validator, balance is locked while staking")

        if xmss_from is None:
            raise LookupError("The source address does not belong to this wallet/node")
        xmss_pk = xmss_from.pk()
        xmss_ots_index = xmss_from.get_index()

        # TODO: Review this
        # Balance validation
        if xmss_from.get_remaining_signatures() == 1:
            balance = self.db_state.balance(addr_from)
            if amount + fee < balance:
                # FIXME: maybe this is too strict?
                raise RuntimeError("Last signature! You must move all the funds to another account!")

        tx = self.create_send_tx(addr_from,
                                 addr_to,
                                 amount,
                                 fee,
                                 xmss_pk,
                                 xmss_ots_index)

        tx.sign(xmss_from)
        self.submit_send_tx(tx)
        return tx

    # FIXME: Rename this appropriately
    def create_send_tx(self,
                       addr_from: bytes,
                       addr_to: bytes,
                       amount: int,
                       fee: int,
                       xmss_pk: bytes,
                       xmss_ots_index: int) -> TransferTransaction:
        balance = self.db_state.balance(addr_from)
        if amount + fee > balance:
            raise RuntimeError("Not enough funds in the source address")

        return TransferTransaction.create(addr_from=addr_from,
                                          addr_to=addr_to,
                                          amount=amount,
                                          fee=fee,
                                          xmss_pk=xmss_pk,
                                          xmss_ots_index=xmss_ots_index)

    # FIXME: Rename this appropriately
    def submit_send_tx(self, tx: TransferTransaction) -> bool:
        if tx is None:
            raise ValueError("The transaction was empty")

        tx.validate_or_raise()

        block_chain_buffer = self._chain.block_chain_buffer
        block_number = block_chain_buffer.height() + 1
        tx_state = block_chain_buffer.get_stxn_state(block_number, tx.txfrom)

        if not tx.validate_extended(tx_state=tx_state, transaction_pool=self._chain.transaction_pool):
            raise ValueError("The transaction failed validatation (blockchain state)")

        self._chain.add_tx_to_pool(tx)
        self._chain.wallet.save_wallet()
        self._p2pfactory.send_tx_to_peers(tx)
        return True

    def get_object(self, query):
        pass
