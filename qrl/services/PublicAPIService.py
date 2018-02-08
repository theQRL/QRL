# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from grpc import StatusCode

from qrl.core import config
from qrl.core.misc import logger
from qrl.core.Transaction import Transaction
from qrl.core.AddressState import AddressState
from qrl.core.qrlnode import QRLNode
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import PublicAPIServicer
from qrl.services.grpcHelper import grpc_exception_wrapper
from pyqrllib.pyqrllib import hstr2bin


class PublicAPIService(PublicAPIServicer):
    MAX_REQUEST_QUANTITY = 100

    # TODO: Separate the Service from the node model
    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode

    @grpc_exception_wrapper(qrl_pb2.GetNodeStateResp, StatusCode.UNKNOWN)
    def GetNodeState(self, request: qrl_pb2.GetNodeStateReq, context) -> qrl_pb2.GetNodeStateResp:
        return qrl_pb2.GetNodeStateResp(info=self.qrlnode.getNodeInfo())

    @grpc_exception_wrapper(qrl_pb2.GetKnownPeersResp, StatusCode.UNKNOWN)
    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        response = qrl_pb2.GetKnownPeersResp()
        response.node_info.CopyFrom(self.qrlnode.getNodeInfo())
        response.known_peers.extend([qrl_pb2.Peer(ip=p) for p in self.qrlnode._peer_addresses])

        return response

    @grpc_exception_wrapper(qrl_pb2.GetStatsResp, StatusCode.UNKNOWN)
    def GetStats(self, request: qrl_pb2.GetStatsReq, context) -> qrl_pb2.GetStatsResp:
        response = qrl_pb2.GetStatsResp()
        response.node_info.CopyFrom(self.qrlnode.getNodeInfo())

        response.epoch = self.qrlnode.epoch
        response.uptime_network = self.qrlnode.uptime_network
        response.block_last_reward = self.qrlnode.block_last_reward
        response.block_time_mean = self.qrlnode.block_time_mean
        response.block_time_sd = self.qrlnode.block_time_sd
        response.coins_total_supply = self.qrlnode.coin_supply_max
        response.coins_emitted = self.qrlnode.coin_supply

        if request.include_timeseries:
            tmp = self.qrlnode.get_block_timeseries(config.dev.block_timeseries_size)
            response.block_timeseries.extend(tmp)

        return response

    @grpc_exception_wrapper(qrl_pb2.GetAddressStateResp, StatusCode.UNKNOWN)
    def GetAddressState(self, request: qrl_pb2.GetAddressStateReq, context) -> qrl_pb2.GetAddressStateResp:
        address_state = self.qrlnode.get_address_state(request.address)
        return qrl_pb2.GetAddressStateResp(state=address_state.pbdata)

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

    @grpc_exception_wrapper(qrl_pb2.TransferCoinsResp, StatusCode.UNKNOWN)
    def GetTokenTxn(self, request: qrl_pb2.TokenTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetTokenTxn")
        tx = self.qrlnode.create_token_txn(addr_from=request.address_from,
                                           symbol=request.symbol,
                                           name=request.name,
                                           owner=request.owner,
                                           decimals=request.decimals,
                                           initial_balances=request.initial_balances,
                                           fee=request.fee,
                                           xmss_pk=request.xmss_pk,
                                           xmss_ots_index=request.xmss_ots_index)

        return qrl_pb2.TransferCoinsResp(transaction_unsigned=tx.pbdata)

    @grpc_exception_wrapper(qrl_pb2.TransferCoinsResp, StatusCode.UNKNOWN)
    def GetTransferTokenTxn(self, request: qrl_pb2.TransferTokenTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetTransferTokenTxn")
        bin_token_txhash = bytes(hstr2bin(request.token_txhash.decode()))
        tx = self.qrlnode.create_transfer_token_txn(addr_from=request.address_from,
                                                    addr_to=request.address_to,
                                                    token_txhash=bin_token_txhash,
                                                    amount=request.amount,
                                                    fee=request.fee,
                                                    xmss_pk=request.xmss_pk,
                                                    xmss_ots_index=request.xmss_ots_index)

        return qrl_pb2.TransferCoinsResp(transaction_unsigned=tx.pbdata)

    @grpc_exception_wrapper(qrl_pb2.TransferCoinsResp, StatusCode.UNKNOWN)
    def GetSlaveTxn(self, request: qrl_pb2.SlaveTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetSlaveTxn")
        tx = self.qrlnode.create_slave_tx(addr_from=request.address_from,
                                          slave_pks=request.slave_pks,
                                          access_types=request.access_types,
                                          fee=request.fee,
                                          xmss_pk=request.xmss_pk,
                                          xmss_ots_index=request.xmss_ots_index)

        return qrl_pb2.TransferCoinsResp(transaction_unsigned=tx.pbdata)

    @grpc_exception_wrapper(qrl_pb2.GetObjectResp, StatusCode.UNKNOWN)
    def GetObject(self, request: qrl_pb2.GetObjectReq, context) -> qrl_pb2.GetObjectResp:
        logger.debug("[PublicAPI] GetObject")
        answer = qrl_pb2.GetObjectResp()
        answer.found = False

        # FIXME: We need a unified way to access and validate data.
        query = bytes(request.query)  # query will be as a string, if Q is detected convert, etc.

        if AddressState.address_is_valid(query):
            if self.qrlnode.get_address_is_used(query):
                address_state = self.qrlnode.get_address_state(query)
                if address_state is not None:
                    answer.found = True
                    answer.address_state.CopyFrom(address_state)
                    return answer

        transaction, block_number = self.qrlnode.get_transaction(query)
        if transaction is not None:
            answer.found = True
            blockheader = None
            if block_number is not None:
                block = self.qrlnode.get_block_from_index(block_number)
                blockheader = block.blockheader.pbdata

            txextended = qrl_pb2.TransactionExtended(header=blockheader,
                                                     tx=transaction.pbdata)
            answer.transaction.CopyFrom(txextended)
            return answer

        block = self.qrlnode.get_block_from_hash(query)
        if block is not None:
            answer.found = True
            answer.block.CopyFrom(block.pbdata)
            return answer

        # NOTE: This is temporary, indexes are accepted for blocks
        try:
            query_str = query.decode()
            query_index = int(query_str)
            block = self.qrlnode.get_block_from_index(query_index)
            if block is not None:
                answer.found = True
                answer.block.CopyFrom(block.pbdata)
                return answer
        except Exception:
            pass

        return answer

    @grpc_exception_wrapper(qrl_pb2.TokenDetailedList, StatusCode.UNKNOWN)
    def GetTokenDetailedList(self, request: qrl_pb2.Empty, context) -> qrl_pb2.TokenDetailedList:
        logger.debug("[PublicAPI] TokenDetailedList")
        token_detailed_list = self.qrlnode.get_token_detailed_list()

        return token_detailed_list

    @grpc_exception_wrapper(qrl_pb2.GetLatestDataResp, StatusCode.UNKNOWN)
    def GetLatestData(self, request: qrl_pb2.GetLatestDataReq, context) -> qrl_pb2.GetLatestDataResp:
        logger.debug("[PublicAPI] GetLatestData")
        response = qrl_pb2.GetLatestDataResp()

        all_requested = request.filter == qrl_pb2.GetLatestDataReq.ALL
        quantity = min(request.quantity, self.MAX_REQUEST_QUANTITY)

        if all_requested or request.filter == qrl_pb2.GetLatestDataReq.BLOCKHEADERS:
            result = []
            for blk in self.qrlnode.get_latest_blocks(offset=request.offset, count=quantity):
                transaction_count = qrl_pb2.TransactionCount()
                for tx in blk.transactions:
                    transaction_count.count[tx.type] += 1

                result.append(qrl_pb2.BlockHeaderExtended(header=blk.blockheader.pbdata,
                                                          transaction_count=transaction_count))
            response.blockheaders.extend(result)

        if all_requested or request.filter == qrl_pb2.GetLatestDataReq.TRANSACTIONS:
            result = []
            for tx in self.qrlnode.get_latest_transactions(offset=request.offset, count=quantity):
                # FIXME: Improve this once we have a proper database schema
                block_index = self.qrlnode.get_blockidx_from_txhash(tx.txhash)
                block = self.qrlnode.get_block_from_index(block_index)
                header = None
                if block:
                    header = block.blockheader.pbdata
                txextended = qrl_pb2.TransactionExtended(header=header,
                                                         tx=tx.pbdata)
                result.append(txextended)

            response.transactions.extend(result)

        if all_requested or request.filter == qrl_pb2.GetLatestDataReq.TRANSACTIONS_UNCONFIRMED:
            result = []
            for tx in self.qrlnode.get_latest_transactions_unconfirmed(offset=request.offset, count=quantity):
                txextended = qrl_pb2.TransactionExtended(header=None,
                                                         tx=tx.pbdata)
                result.append(txextended)
            response.transactions_unconfirmed.extend(result)

        return response

    @grpc_exception_wrapper(qrl_pb2.PushTransactionResp, StatusCode.UNKNOWN)
    def PushEphemeralMessage(self, request: qrl_pb2.PushEphemeralMessageReq, context) -> qrl_pb2.PushTransactionResp:
        logger.debug("[PublicAPI] PushEphemeralMessageReq")
        submitted = False

        if config.user.accept_ephemeral:
            encrypted_ephemeral_message = EncryptedEphemeralMessage(request.ephemeral_message)
            submitted = self.qrlnode.broadcast_ephemeral_message(encrypted_ephemeral_message)

        answer = qrl_pb2.PushTransactionResp()
        answer.some_response = str(submitted)
        return answer

    @grpc_exception_wrapper(qrl_pb2.PushTransactionResp, StatusCode.UNKNOWN)
    def CollectEphemeralMessage(self,
                                request: qrl_pb2.CollectEphemeralMessageReq,
                                context) -> qrl_pb2.CollectEphemeralMessageResp:
        logger.debug("[PublicAPI] CollectEphemeralMessage")

        ephemeral_metadata = self.qrlnode.collect_ephemeral_message(request.msg_id)
        answer = qrl_pb2.CollectEphemeralMessageResp(ephemeral_metadata=ephemeral_metadata.pbdata)
        return answer
