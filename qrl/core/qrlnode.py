import decimal
import os

from decimal import Decimal

import time
from typing import Optional, List

from qrl.core import config, logger
from qrl.core.BufferedChain import BufferedChain
from qrl.core.StakeValidator import StakeValidator
from qrl.core.Transaction import TransferTransaction, Transaction, LatticePublicKey
from qrl.core.Block import Block
from qrl.core.ESyncState import ESyncState
from qrl.core.State import State
from qrl.generated import qrl_pb2


# FIXME: This will soon move to core. Split/group functionality
class QRLNode:
    def __init__(self, db_state: State):
        self.start_time = time.time()

        self._peer_addresses = []
        self.peers_path = os.path.join(config.user.data_path, config.dev.peers_filename)
        self._load_peer_addresses()

        self.db_state = db_state
        self._buffered_chain = None  # FIXME: REMOVE. This is temporary
        self._p2pfactory = None  # FIXME: REMOVE. This is temporary

    @property
    def version(self):
        # FIXME: Move to __version__ coming from pip
        return config.dev.version

    @property
    def state(self):
        if self._p2pfactory is None:
            return ESyncState.unknown.value
        # FIXME
        return self._p2pfactory.sync_state.state.value

    @property
    def num_connections(self):
        if self._p2pfactory is None:
            return 0
        # FIXME
        return self._p2pfactory.connections

    @property
    def num_known_peers(self):
        # FIXME
        return len(self._peer_addresses)

    @property
    def uptime(self):
        return int(time.time() - self.start_time)

    @property
    def block_height(self):
        return self._buffered_chain.height

    @property
    def staking(self):
        if self._p2pfactory is None:
            return False
        return self._p2pfactory.pos.stake

    @property
    def epoch(self):
        if len(self._buffered_chain._chain.blockchain) == 0:
            return 0
        return self._buffered_chain._chain.blockchain[-1].epoch

    @property
    def uptime_network(self):
        block_one = self._buffered_chain.get_block(1)
        network_uptime = 0
        if block_one:
            network_uptime = int(time.time() - block_one.timestamp)
        return network_uptime

    @property
    def stakers_count(self):
        return len(self.db_state.stake_validators_tracker.sv_dict)

    @property
    def block_last_reward(self):
        if len(self._buffered_chain._chain.blockchain) == 0:
            return 0

        return self._buffered_chain._chain.blockchain[-1].block_reward

    @property
    def block_time_mean(self):
        # FIXME: Keep a moving mean
        return 0

    @property
    def block_time_sd(self):
        # FIXME: Keep a moving var
        return 0

    @property
    def coin_supply(self):
        # FIXME: Keep a moving var
        return self.db_state.total_coin_supply()

    @property
    def coin_supply_max(self):
        # FIXME: Keep a moving var
        return config.dev.max_coin_supply

    @property
    def coin_atstake(self):
        # FIXME: This is very time consuming.. (moving from old code) improve/cache
        total_at_stake = 0
        for staker in self.db_state.stake_validators_tracker.sv_dict:
            total_at_stake += self.db_state.balance(staker)
        return total_at_stake

    @property
    def peer_addresses(self):
        return self._peer_addresses

    @property
    def addresses(self) -> List[bytes]:
        return self._buffered_chain.wallet.addresses

    # FIXME: REMOVE. This is temporary
    def set_chain(self, buffered_chain: BufferedChain):
        self._buffered_chain = buffered_chain

    # FIXME: REMOVE. This is temporary
    def set_p2pfactory(self, p2pfactory):
        self._p2pfactory = p2pfactory

    def _load_peer_addresses(self) -> None:
        try:
            if os.path.isfile(self.peers_path):
                logger.info('Opening peers.qrl')
                with open(self.peers_path, 'rb') as infile:
                    known_peers = qrl_pb2.StoredPeers()
                    known_peers.ParseFromString(infile.read())
                    self._peer_addresses = [peer.ip for peer in known_peers.peers]
                    self._peer_addresses.extend(config.user.peer_list)
                    return
        except Exception as e:
            logger.warning("Error loading peers")
            logger.exception(e)

        logger.info('Creating peers.qrl')
        # Ensure the data path exists
        config.create_path(config.user.data_path)
        self.update_peer_addresses(config.user.peer_list)

        logger.info('Known Peers: %s', self._peer_addresses)

    def update_peer_addresses(self, peer_addresses) -> None:
        # FIXME: Probably will be refactored
        self._peer_addresses = peer_addresses
        known_peers = qrl_pb2.StoredPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in set(self._peer_addresses)])
        with open(self.peers_path, "wb") as outfile:
            outfile.write(known_peers.SerializeToString())

    @staticmethod
    def get_dec_amount(str_amount_arg: str) -> Decimal:
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

            num_wallets = len(self._buffered_chain.wallet.address_bundle)
            addr_idx = int(addr_or_index)
            if 0 <= addr_idx < num_wallets:
                return self._buffered_chain.wallet.address_bundle[addr_idx].address
            else:
                raise ValueError("invalid address index")

        if addr_or_index[0] != ord('Q'):
            raise ValueError("Invalid address")

        return addr_or_index

    @staticmethod
    def validate_amount(amount_str: str) -> bool:
        # FIXME: Refactored code. Review Decimal usage all over the code
        Decimal(amount_str)
        return True

    def _find_xmss(self, key_addr: bytes):
        # FIXME: Move down the wallet management
        for addr in self._buffered_chain.wallet.address_bundle:
            if addr.address == key_addr:
                return addr.xmss
        return None

    # FIXME: Rename this appropriately
    def transfer_coins(self, addr_from: bytes, addr_to: bytes, amount: int, fee: int = 0):
        block_chain_buffer = self._buffered_chain.block_chain_buffer
        stake_validators_tracker = block_chain_buffer.get_stake_validators_tracker(block_chain_buffer.height() + 1)

        xmss_from = self._find_xmss(addr_from)

        if addr_from in stake_validators_tracker.sv_dict and stake_validators_tracker.sv_dict[addr_from].is_active:
            raise LookupError("Source address is a Stake Validator, balance is locked while staking")

        if (addr_from in stake_validators_tracker.future_stake_addresses and
                stake_validators_tracker.future_stake_addresses[addr_from].is_active):
            raise LookupError("Source address is a Future Stake Validator, balance is locked")

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

    def create_lt(self,
                  addr_from: bytes,
                  kyber_pk: bytes,
                  tesla_pk: bytes,
                  xmss_pk: bytes,
                  xmss_ots_index: int) -> LatticePublicKey:

        return LatticePublicKey.create(addr_from=addr_from,
                                       kyber_pk=kyber_pk,
                                       tesla_pk=tesla_pk,
                                       xmss_pk=xmss_pk,
                                       xmss_ots_index=xmss_ots_index)

    # FIXME: Rename this appropriately
    def submit_send_tx(self, tx: TransferTransaction) -> bool:
        if tx is None:
            raise ValueError("The transaction was empty")

        if tx.subtype == qrl_pb2.Transaction.LATTICE:
            self._p2pfactory.broadcast_lt(tx)
        elif tx.subtype == qrl_pb2.Transaction.TRANSFER:
            tx.validate_or_raise()

            block_number = self._buffered_chain.height + 1
            tx_state = self._buffered_chain.get_stxn_state(block_number, tx.txfrom)

            if not tx.validate_extended(tx_state=tx_state, transaction_pool=self._buffered_chain.tx_pool.transaction_pool):
                raise ValueError("The transaction failed validatation (blockchain state)")

            self._buffered_chain.tx_pool.add_tx_to_pool(tx)
            self._buffered_chain.wallet.save_wallet()
            self._p2pfactory.broadcast_tx(tx)

        return True

    @staticmethod
    def address_is_valid(address: bytes) -> bool:
        # TODO: Validate address format
        if len(address) < 1:
            return False

        if address[0] != ord('Q'):
            return False

        return True

    def get_address_is_used(self, address: bytes) -> bool:
        if not self.address_is_valid(address):
            raise ValueError("Invalid Address")

        return self.db_state.address_used(address)

    def get_address_state(self, address: bytes) -> qrl_pb2.AddressState:
        if not self.address_is_valid(address):
            raise ValueError("Invalid Address")

        tmp_address_state = self.db_state.get_address(address)
        transaction_hashes = self.db_state.get_address_tx_hashes(address)
        address_state = qrl_pb2.AddressState(address=tmp_address_state.address,
                                             balance=tmp_address_state.balance,
                                             nonce=tmp_address_state.nonce,
                                             pubhashes=tmp_address_state.pubhashes,
                                             transaction_hashes=transaction_hashes)

        return address_state

    def get_transaction(self, query_hash: bytes) -> Optional[Transaction]:
        """
        This method returns an object that matches the query hash
        """
        # FIXME: At some point, all objects in DB will indexed by a hash
        # TODO: Search tx hash
        # FIXME: We dont need searches, etc.. getting a protobuf indexed by hash from DB should be enough
        # FIXME: This is just a workaround to provide functionality
        for tx in self._buffered_chain.tx_pool.transaction_pool:
            if tx.txhash == query_hash:
                return tx
        return None

    def get_block_from_hash(self, query_hash: bytes) -> Optional[Block]:
        """
        This method returns an object that matches the query hash
        """
        # FIXME: At some point, all objects in DB will indexed by a hash
        return None

    def get_block_from_index(self, index: int) -> Block:
        """
        This method returns an object that matches the query hash
        """
        # FIXME: At some point, all objects in DB will indexed by a hash
        return self._buffered_chain.get_block(index)

    def get_current_stakers(self, offset, count) -> List[StakeValidator]:
        stakers = list(self.db_state.stake_validators_tracker.sv_dict.values())
        start = min(offset, len(stakers))
        end = min(start + count, len(stakers))
        return stakers[start:end]

    def get_next_stakers(self, offset, count) -> List[StakeValidator]:
        stakers = list(self.db_state.stake_validators_tracker.sv_dict.values())
        start = min(offset, len(stakers))
        end = min(start + count, len(stakers))
        return stakers[start:end]

    def get_latest_blocks(self, offset, count) -> List[Block]:
        # FIXME: This is incorrect. Offset does not work
        answer = []
        end = self.block_height - offset
        start = max(0, end - count - offset)
        for blk_idx in range(start, end):
            answer.append(self._buffered_chain.get_block(blk_idx))

        return answer

    def get_latest_transactions(self, offset, count):
        # FIXME: This is incorrect
        # FIXME: Moved code. Breaking encapsulation. Refactor
        if not self._buffered_chain._chain.blockchain:
            return []

        last_block = self._buffered_chain._chain.blockchain[-1]

        answer = []
        skipped = 0
        for pbtx in reversed(last_block.transactions):
            tx = Transaction.from_pbdata(pbtx)
            if isinstance(tx, TransferTransaction):
                if skipped >= offset:
                    answer.append(tx)
                    if len(answer) >= count:
                        break
                else:
                    skipped += 1

        return answer

    def get_latest_transactions_unconfirmed(self, offset, count):
        answer = []
        skipped = 0
        for tx in reversed(self._buffered_chain.tx_pool.transaction_pool):
            if isinstance(tx, TransferTransaction):
                if skipped >= offset:
                    answer.append(tx)
                    if len(answer) >= count:
                        break
                else:
                    skipped += 1
        return answer

    def getNodeInfo(self) -> qrl_pb2.NodeInfo:
        info = qrl_pb2.NodeInfo()
        info.version = self.version
        info.state = self.state
        info.num_connections = self.num_connections
        info.num_known_peers = self.num_known_peers
        info.uptime = self.uptime
        info.block_height = self.block_height
        info.block_last_hash = b''  # FIXME
        info.stake_enabled = self.staking
        info.network_id = config.dev.genesis_prev_headerhash  # FIXME
        return info
