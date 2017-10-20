# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from grpc import StatusCode

from qrl.core import logger
from qrl.core.Transaction import Transaction
from qrl.core.qrlnode import QRLNode
from qrl.generated.qrl_pb2 import *
from qrl.services.grpcHelper import grpc_exception_wrapper


class PublicAPIService(PublicAPIServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode

    @grpc_exception_wrapper(GetNodeStateResp, StatusCode.UNKNOWN)
    def GetNodeState(self, request: GetNodeStateReq, context) -> GetNodeStateResp:
        info = NodeInfo()
        info.version = self.qrlnode.version
        info.state = self.qrlnode.state
        info.num_connections = self.qrlnode.num_connections
        info.num_known_peers = self.qrlnode.num_known_peers
        info.uptime = self.qrlnode.uptime
        info.block_height = self.qrlnode.block_height
        info.stake_enabled = self.qrlnode.staking
        return GetNodeStateResp(info=info)

    @grpc_exception_wrapper(GetKnownPeersResp, StatusCode.UNKNOWN)
    def GetKnownPeers(self, request: GetKnownPeersReq, context) -> GetKnownPeersResp:
        known_peers = KnownPeers()
        known_peers.peers.extend([Peer(ip=p) for p in self.qrlnode.peer_addresses])
        return GetKnownPeersResp(known_peers=known_peers)

    @grpc_exception_wrapper(GetAddressStateResp, StatusCode.UNKNOWN)
    def GetAddressState(self, request: GetAddressStateReq, context) -> GetAddressStateResp:
        address_state = self.qrlnode.get_address_state(request.address)
        return GetAddressStateResp(state=address_state)

    @grpc_exception_wrapper(TransferCoinsResp, StatusCode.UNKNOWN)
    def TransferCoins(self, request: TransferCoinsReq, context) -> TransferCoinsResp:
        logger.debug("[QRLNode] TransferCoins")
        tx = self.qrlnode.create_send_tx(addr_from=request.address_from,
                                         addr_to=request.address_to,
                                         amount=request.amount,
                                         fee=request.fee,
                                         xmss_pk=request.xmss_pk,
                                         xmss_ots_index=request.xmss_ots_index)

        return TransferCoinsResp(transaction_unsigned=tx.pbdata)

    @grpc_exception_wrapper(TransferCoinsResp, StatusCode.UNKNOWN)
    def PushTransaction(self, request: PushTransactionReq, context) -> PushTransactionResp:
        logger.debug("[QRLNode] PushTransaction")
        tx = Transaction.from_pbdata(request.transaction_signed)
        submitted = self.qrlnode.submit_send_tx(tx)

        # FIXME: Improve response type
        # Prepare response
        answer = PushTransactionResp()
        answer.some_response = str(submitted)
        return answer
