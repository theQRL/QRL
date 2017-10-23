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

    def _getNodeInfo(self):
        info = qrl_pb2.NodeInfo()
        info.version = self.qrlnode.version
        info.state = self.qrlnode.state
        info.num_connections = self.qrlnode.num_connections
        info.num_known_peers = self.qrlnode.num_known_peers
        info.uptime = self.qrlnode.uptime
        info.block_height = self.qrlnode.block_height
        info.block_last_hash = b''  # FIXME
        info.stake_enabled = self.qrlnode.staking
        info.network_id = '???'  # FIXME
        return info

    @grpc_exception_wrapper(qrl_pb2.GetStatsResp, StatusCode.UNKNOWN)
    def GetStats(self, request: qrl_pb2.GetStatsReq, context) -> qrl_pb2.GetStatsResp:
        response = qrl_pb2.GetStatsResp()
        response.node_info.CopyFrom(self._getNodeInfo())

        response.epoch = self.qrlnode.epoch
        response.uptime_network = self.qrlnode.uptime_network
        response.stakers_count = self.qrlnode.stakers_count
        response.block_last_reward = self.qrlnode.block_last_reward
        response.block_time_mean = self.qrlnode.block_time_mean
        response.block_time_sd = self.qrlnode.block_time_sd
        response.coins_total_supply = self.qrlnode.coin_supply_max  # FIXME
        response.coins_emitted = self.qrlnode.coin_supply
        response.coins_atstake = self.qrlnode.coin_atstake

        return response

    @grpc_exception_wrapper(qrl_pb2.GetNodeStateResp, StatusCode.UNKNOWN)
    def GetNodeState(self, request: qrl_pb2.GetNodeStateReq, context) -> qrl_pb2.GetNodeStateResp:
        return qrl_pb2.GetNodeStateResp(info=self._getNodeInfo())

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
        answer.found = False

        # FIXME: We need a unified way to access and validate data.
        query = bytes(request.query)  # query will be as a string, if Q is detected convert, etc.

        address_state = self.qrlnode.get_address_state(query)
        if address_state is not None:
            answer.found = True
            answer.address_state = address_state
            return answer

        transaction = self.qrlnode.get_transaction(query)
        if transaction is not None:
            answer.found = True
            answer.transaction = transaction.pbdata
            return answer

        try:
            block = self.qrlnode.get_transaction(query)
            if block is not None:
                answer.found = True
                answer.block = block.pbdata
                return answer
        except NotImplementedError as e:
            # FIXME: implementation missing
            answer.found = True
            pass

        return answer

    @grpc_exception_wrapper(qrl_pb2.GetLatestDataResp, StatusCode.UNKNOWN)
    def GetLatestData(self, request: qrl_pb2.GetLatestDataReq, context) -> qrl_pb2.GetLatestDataResp:
        logger.debug("[PublicAPI] GetLatestData")
        response = qrl_pb2.GetLatestDataResp()

        response.blocks.extend([blk.pbdata for blk in self.qrlnode.get_latest_blocks()])
        response.transactions.extend([tx.pbdata for tx in self.qrlnode.get_latest_transactions()])
        response.transactions_unconfirmed.extend([tx.pbdata for tx in self.qrlnode.get_latest_transactions_unconfirmed()])

        return response
