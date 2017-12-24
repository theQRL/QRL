# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from grpc import StatusCode

from qrl.core import logger
from qrl.core.StakeValidator import StakeValidator
from qrl.core.Transaction import Transaction
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import PublicAPIServicer
from qrl.services.grpcHelper import grpc_exception_wrapper


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
        response.stakers_count = self.qrlnode.stakers_count
        response.block_last_reward = self.qrlnode.block_last_reward
        response.block_time_mean = self.qrlnode.block_time_mean
        response.block_time_sd = self.qrlnode.block_time_sd
        response.coins_total_supply = self.qrlnode.coin_supply_max
        response.coins_emitted = self.qrlnode.coin_supply
        response.coins_atstake = self.qrlnode.coin_atstake

        return response

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

    @grpc_exception_wrapper(qrl_pb2.UnsignedTransactionResp, StatusCode.UNKNOWN)
    def GetUnsignedTransaction(self, request: qrl_pb2.UnsignedTransactionReq, context) -> qrl_pb2.UnsignedTransactionResp:
        logger.debug("[PublicAPI] GetUnsignedTxn")
        tx = self.qrlnode.create_unsigned_tx(request.transaction)
        response = None
        if tx:
            response = tx.pbdata
        return qrl_pb2.UnsignedTransactionResp(transaction=response)

    @grpc_exception_wrapper(qrl_pb2.TransferCoinsResp, StatusCode.UNKNOWN)
    def GetLatticePublicKeyTxn(self, request: qrl_pb2.LatticePublicKeyTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetLatticePublicKeyTxn")
        tx = self.qrlnode.create_lt(addr_from=request.address_from,
                                    kyber_pk=request.kyber_pk,
                                    tesla_pk=request.tesla_pk,
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

        if self.qrlnode.address_is_valid(query):
            if self.qrlnode.get_address_is_used(query):
                address_state = self.qrlnode.get_address_state(query)
                if address_state is not None:
                    answer.found = True
                    answer.address_state.CopyFrom(address_state)
                    return answer

        transaction = self.qrlnode.get_transaction(query)
        if transaction is not None:
            answer.found = True
            block_index = self.qrlnode.get_blockidx_from_txhash(transaction.txhash)
            blockheader = None
            if block_index:
                block = self.qrlnode.get_block_from_index(block_index)
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

    def _stake_validator_to_staker_data(self, stake_validator: StakeValidator) -> qrl_pb2.StakerData:
        answer = qrl_pb2.StakerData()
        answer.address_state.CopyFrom(self.qrlnode.get_address_state(stake_validator.address))
        answer.terminator_hash = stake_validator.terminator_hash
        return answer

    @grpc_exception_wrapper(qrl_pb2.GetStakersResp, StatusCode.UNKNOWN)
    def GetStakers(self, request: qrl_pb2.GetStakersReq, context) -> qrl_pb2.GetStakersResp:
        logger.debug("[PublicAPI] GetStakers")
        response = qrl_pb2.GetStakersResp()
        quantity = min(request.quantity, self.MAX_REQUEST_QUANTITY)

        if request.filter == qrl_pb2.GetStakersReq.CURRENT:
            sv_list = self.qrlnode.get_current_stakers(offset=request.offset, count=quantity)
        elif request.filter == qrl_pb2.GetStakersReq.NEXT:
            sv_list = self.qrlnode.get_next_stakers(offset=request.offset, count=quantity)
        else:
            raise NotImplementedError("filter value is not supported")

        sv_data = [self._stake_validator_to_staker_data(sv) for sv in sv_list]
        response.stakers.extend(sv_data)
        return response

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
                for tx in blk.vote:
                    transaction_count.count[tx.type] += 1
                for tx in blk.duplicate_transactions:
                    transaction_count.count[tx.type] += 1

                voted_weight = 0
                total_stake_weight = 0
                if blk.block_number > 0:
                    voted_weight, total_stake_weight = self.qrlnode.get_vote_metadata(blk.block_number)

                result.append(qrl_pb2.BlockHeaderExtended(header=blk.blockheader.pbdata,
                                                          transaction_count=transaction_count,
                                                          voted_weight=voted_weight,
                                                          total_stake_weight=total_stake_weight))
            response.blockheaders.extend(result)

        if all_requested or request.filter == qrl_pb2.GetLatestDataReq.TRANSACTIONS:
            result = []
            for tx in self.qrlnode.get_latest_transactions(offset=request.offset, count=quantity):
                # FIXME: Improve this once we have a proper database schema
                block_index = self.qrlnode.get_blockidx_from_txhash(tx.txhash)
                block = self.qrlnode.get_block_from_index(block_index)
                txextended = qrl_pb2.TransactionExtended(header=block.blockheader.pbdata,
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
