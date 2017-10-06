import os

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

        self.chain = None               # FIXME: REMOVE. This is temporary
        self.p2pfactory = None          # FIXME: REMOVE. This is temporary

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
        # FIXME: Refactor.
        nonce, balance, pubhash_list = self.db_state.state_get_address(address)
        transactions = []

        address_state = qrl_pb2.AddressState(address=address,
                                             balance=balance,
                                             nonce=nonce,
                                             transactions=transactions)

        return address_state

    def create_send_tx(self, addr_from, addr_to, amount, fee=0):
        tx = self.chain.create_send_tx(addr_from, addr_to, amount, fee)
        self.chain.submit_send_tx(tx)

    def _get_xmss(self, key_addr):
        for addr in self.chain.wallet.address_bundle:
            if addr.address == key_addr:
                return addr.xmss
        return None

    def create_send_tx(self, addr_from, addr_to, amount, fee=0):
        # FIXME: This method is not about the chain. It is about operations (should be on a higher level)

        xmss_from = self._get_xmss(addr_from)
        if xmss_from is None:
            raise LookupError("The source address could not be found")

        block_number = self.chain.block_chain_buffer.height() + 1

        tx_state = self.chain.block_chain_buffer.get_stxn_state(block_number, addr_from)

        tx = SimpleTransaction.create(addr_from=addr_from,
                                      addr_to=addr_to,
                                      amount=amount,
                                      xmss_pk=xmss_from.pk(),
                                      xmss_ots_key=xmss_from.get_index(),
                                      fee=fee)

        tx.sign(xmss_from)

        return tx

    def submit_send_tx(self, tx):
        if tx and tx.state_validate_tx(tx_state=tx_state, transaction_pool=self.chain.transaction_pool):
            self.chain.add_tx_to_pool(tx)
            self.chain.wallet.save_wallet()
            # need to keep state after tx ..use self.wallet.info to store index..
            # far faster than loading the 55mb self.wallet..
            return True

        return False
