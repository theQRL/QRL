import decimal
import os

from decimal import Decimal

from qrl.core import config, logger
from qrl.core.Transaction import SimpleTransaction
from qrl.core.state import State
from qrl.generated import qrl_pb2


# FIXME: This will soon move to core
class QRLNode:
    def __init__(self, db_state: State):
        self.peer_addresses = []
        self.peers_path = os.path.join(config.user.data_path, config.dev.peers_filename)
        self.load_peer_addresses()

        self.db_state = db_state

        self.chain = None  # FIXME: REMOVE. This is temporary
        self.p2pfactory = None  # FIXME: REMOVE. This is temporary

    # FIXME: REMOVE. This is temporary
    def set_chain(self, chain):
        self.chain = chain

    # FIXME: REMOVE. This is temporary
    def set_p2pfactory(self, p2pfactory):
        self.p2pfactory = p2pfactory

    def load_peer_addresses(self):
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

        logger.info('Creating peers.qrl')
        # Ensure the data path exists
        config.create_path(config.user.data_path)
        self.update_peer_addresses(config.user.peer_list)

        logger.info('Known Peers: %s', self.peer_addresses)

    def update_peer_addresses(self, peer_addresses):
        # FIXME: Probably will be refactored
        self.peer_addresses = peer_addresses
        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.peer_addresses])
        with open(self.peers_path, "wb") as outfile:
            outfile.write(known_peers.SerializeToString())

    def get_address_state(self, address):
        # FIXME: Refactor. Define concerns, etc.
        nonce, balance, pubhash_list = self.db_state.state_get_address(address)
        transactions = []

        address_state = qrl_pb2.AddressState(address=address,
                                             balance=balance,
                                             nonce=nonce,
                                             transactions=transactions)

        return address_state

    def get_dec_amount(self, str_amount_arg):
        # FIXME: Concentrating logic into a single point. Fix this, make type safe to avoid confusion. Quantity formats should be always clear
        # FIXME: Review. This is just relocated code. It looks odd
        # FIXME: Antipattern. Magic number.
        # FIXME: Validate string, etc.
        return decimal.Decimal(decimal.Decimal(str_amount_arg) * 100000000).quantize(decimal.Decimal('1'),
                                                                                     rounding=decimal.ROUND_HALF_UP)

    def get_wallet_absolute(self, addr_or_index):
        # FIXME: Refactor. Define concerns, etc. Validation vs logic
        if not addr_or_index:
            raise ValueError("address is empty")

        if addr_or_index.isdigit():
            # FIXME: The whole idea of accepting relative (index based) wallets internally is flawed.
            # There is a risk of confusing things. Relative should be a feature of UIs

            num_wallets = len(self.chain.wallet.address_bundle)
            addr_idx = int(addr_or_index)
            if 0 <= addr_idx < num_wallets:
                return self.chain.wallet.address_bundle[addr_idx].get_address()
            else:
                raise ValueError("invalid address index")

        if addr_or_index[0] != 'Q':
            raise ValueError("Invalid address")

        return addr_or_index

    def validate_amount(self, amount_str):
        # FIXME: Refactored code. Review Decimal usage all over the code
        amount = Decimal(amount_str)

    def _find_xmss(self, key_addr):
        # FIXME: Move down the wallet management
        for addr in self.chain.wallet.address_bundle:
            if addr.address == key_addr:
                return addr.xmss
        return None

    def transfer_coins(self, addr_from, addr_to, amount, fee=0):
        xmss_from = self._find_xmss(addr_from)
        if xmss_from is None:
            raise LookupError("The source address does not belong to this wallet/node")
        xmss_pk = xmss_from.pk()
        xmss_ots_key = xmss_from.get_index()

        # TODO: Review this
        ### Balance validation
        balance = self.db_state.state_balance(addr_from)
        if amount + fee > balance:
            raise RuntimeError("Not enough funds")

        if xmss_from.get_remaining_signatures() == 1:
            if amount + fee < balance:
                # FIXME: maybe this is too strict?
                raise RuntimeError("Last signature! You must move all the funds to another account!")

        tx = self.create_send_tx(addr_from,
                                 addr_to,
                                 amount,
                                 fee,
                                 xmss_pk,
                                 xmss_ots_key)

        tx.sign(xmss_from)
        self.submit_send_tx(tx)
        self.p2pfactory.send_tx_to_peers(tx)

        return tx

    def create_send_tx(self, addr_from, addr_to, amount, fee, xmss_pk, xmss_ots_key):
        return SimpleTransaction.create(addr_from=addr_from,
                                        addr_to=addr_to,
                                        amount=amount,
                                        fee=fee,
                                        xmss_pk=xmss_pk,
                                        xmss_ots_key=xmss_ots_key)

    def submit_send_tx(self, tx):
        # TODO: Review this
        if tx and tx.validate_tx():
            block_chain_buffer = self.chain.block_chain_buffer
            block_number = block_chain_buffer.height() + 1
            tx_state = block_chain_buffer.get_stxn_state(block_number, tx.txto)

            if tx.state_validate_tx(tx_state=tx_state, transaction_pool=self.chain.transaction_pool):
                self.chain.add_tx_to_pool(tx)
                self.chain.wallet.save_wallet()
                return True

        return False
