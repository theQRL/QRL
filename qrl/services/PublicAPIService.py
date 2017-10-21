# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from grpc import StatusCode

from qrl.core import logger
from qrl.core.Transaction import Transaction
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.services.grpcHelper import grpc_exception_wrapper


class PublicAPIService(qrl_pb2.PublicAPIServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode

    @grpc_exception_wrapper(qrl_pb2.GetNodeStateResp, StatusCode.UNKNOWN)
    def GetNodeState(self, request: qrl_pb2.GetNodeStateReq, context) -> qrl_pb2.GetNodeStateResp:
        info = qrl_pb2.NodeInfo()
        info.version = self.qrlnode.version
        info.state = self.qrlnode.state
        info.num_connections = self.qrlnode.num_connections
        info.num_known_peers = self.qrlnode.num_known_peers
        info.uptime = self.qrlnode.uptime
        info.block_height = self.qrlnode.block_height
        info.stake_enabled = self.qrlnode.staking
        return qrl_pb2.GetNodeStateResp(info=info)

    @grpc_exception_wrapper(qrl_pb2.GetKnownPeersResp, StatusCode.UNKNOWN)
    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        known_peers = qrl_pb2.KnownPeers()
        known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.qrlnode.peer_addresses])
        return qrl_pb2.GetKnownPeersResp(known_peers=known_peers)

    @grpc_exception_wrapper(qrl_pb2.GetAddressStateResp, StatusCode.UNKNOWN)
    def GetAddressState(self, request: qrl_pb2.GetAddressStateReq, context) -> qrl_pb2.GetAddressStateResp:
        address_state = self.qrlnode.get_address_state(request.address)
        return qrl_pb2.GetAddressStateResp(state=address_state)

    @grpc_exception_wrapper(qrl_pb2.TransferCoinsResp, StatusCode.UNKNOWN)
    def TransferCoins(self, request: qrl_pb2.TransferCoinsReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] TransferCoins")
        tx = self.qrlnode.create_send_tx(addr_from=request.address_from,
                                         addr_to=request.address_to,
                                         amount=request.amount,
                                         fee=request.fee,
                                         xmss_pk=request.xmss_pk,
                                         xmss_ots_index=request.xmss_ots_index)

        return qrl_pb2.TransferCoinsResp(transaction_unsigned=tx.pbdata)

    @grpc_exception_wrapper(qrl_pb2.TransferCoinsResp, StatusCode.UNKNOWN)
    def PushTransaction(self, request: qrl_pb2.PushTransactionReq, context) -> qrl_pb2.PushTransactionResp:
        logger.debug("[PublicAPI] PushTransaction")
        tx = Transaction.from_pbdata(request.transaction_signed)
        submitted = self.qrlnode.submit_send_tx(tx)

        # FIXME: Improve response type
        # Prepare response
        answer = qrl_pb2.PushTransactionResp()
        answer.some_response = str(submitted)
        return answer

    @grpc_exception_wrapper(qrl_pb2.GetObjectResp, StatusCode.UNKNOWN)
    def GetObject(self, request: qrl_pb2.GetObjectReq, context) -> qrl_pb2.GetObjectResp:
        logger.debug("[PublicAPI] GetObject")
        answer = qrl_pb2.GetObjectResp

        # FIXME: encapsulate in qrlnode. Queries should be just hashes

        # FIXME: We need a unified way to access and validate data.
        query = bytes(request.query)    # query will be as a string, if Q is detected convert, etc.

        address_state = self.qrlnode.get_address_state(query)
        if address_state is not None:
            answer.found = True
            answer.address_state = address_state
            return answer

        # TODO: Search tx hash
        # FIXME: We dont need searches, etc.. getting a protobuf indexed by hash from DB should be enough
        # FIXME: workaround to provide functionality
        for tx in self.qrlnode._chain.transaction_pool:
            if tx.txhash == query:
                answer.found = True
                answer.transaction = tx
                return answer

        # TODO: Get tx from db (they should be stored as pb)

        return answer
