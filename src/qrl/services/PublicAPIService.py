# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import traceback

from pyqrllib.pyqrllib import hstr2bin, QRLHelper

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.Transaction import Transaction, CODEMAP
from qrl.core.misc import logger
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import PublicAPIServicer
from qrl.services.grpcHelper import GrpcExceptionWrapper


class PublicAPIService(PublicAPIServicer):
    MAX_REQUEST_QUANTITY = 100

    # TODO: Separate the Service from the node model
    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode

    @GrpcExceptionWrapper(qrl_pb2.GetAddressFromPKResp)
    def GetAddressFromPK(self, request: qrl_pb2.GetAddressFromPKReq, context) -> qrl_pb2.GetAddressFromPKResp:
        return qrl_pb2.GetAddressFromPKResp(address=bytes(QRLHelper.getAddress(request.pk)))

    @GrpcExceptionWrapper(qrl_pb2.GetPeersStatResp)
    def GetPeersStat(self, request: qrl_pb2.GetPeersStatReq, context) -> qrl_pb2.GetPeersStatResp:
        peers_stat_resp = qrl_pb2.GetPeersStatResp()
        peers_stat = self.qrlnode.get_peers_stat()

        for stat in peers_stat:
            peers_stat_resp.peers_stat.extend([stat])

        return peers_stat_resp

    @GrpcExceptionWrapper(qrl_pb2.GetNodeStateResp)
    def GetNodeState(self, request: qrl_pb2.GetNodeStateReq, context) -> qrl_pb2.GetNodeStateResp:
        return qrl_pb2.GetNodeStateResp(info=self.qrlnode.getNodeInfo())

    @GrpcExceptionWrapper(qrl_pb2.GetKnownPeersResp)
    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        response = qrl_pb2.GetKnownPeersResp()
        response.node_info.CopyFrom(self.qrlnode.getNodeInfo())
        response.known_peers.extend([qrl_pb2.Peer(ip=p) for p in self.qrlnode._peer_addresses])

        return response

    @GrpcExceptionWrapper(qrl_pb2.GetStatsResp)
    def GetStats(self, request: qrl_pb2.GetStatsReq, context) -> qrl_pb2.GetStatsResp:
        response = qrl_pb2.GetStatsResp()
        response.node_info.CopyFrom(self.qrlnode.getNodeInfo())

        response.epoch = self.qrlnode.epoch
        response.uptime_network = self.qrlnode.uptime_network
        response.block_last_reward = self.qrlnode.block_last_reward
        response.block_time_mean = self.qrlnode.block_time_mean
        response.block_time_sd = self.qrlnode.block_time_sd
        response.coins_total_supply = int(self.qrlnode.coin_supply_max)
        response.coins_emitted = int(self.qrlnode.coin_supply)

        if request.include_timeseries:
            tmp = self.qrlnode.get_block_timeseries(config.dev.block_timeseries_size)
            response.block_timeseries.extend(tmp)

        return response

    @GrpcExceptionWrapper(qrl_pb2.GetAddressStateResp)
    def GetAddressState(self, request: qrl_pb2.GetAddressStateReq, context) -> qrl_pb2.GetAddressStateResp:
        address_state = self.qrlnode.get_address_state(request.address)
        return qrl_pb2.GetAddressStateResp(state=address_state.pbdata)

    @GrpcExceptionWrapper(qrl_pb2.TransferCoinsResp)
    def TransferCoins(self, request: qrl_pb2.TransferCoinsReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] TransferCoins")
        tx = self.qrlnode.create_send_tx(addrs_to=request.addresses_to,
                                         amounts=request.amounts,
                                         fee=request.fee,
                                         xmss_pk=request.xmss_pk,
                                         master_addr=request.master_addr)

        extended_transaction_unsigned = qrl_pb2.TransactionExtended(tx=tx.pbdata,
                                                                    addr_from=tx.addr_from,
                                                                    size=tx.size)
        return qrl_pb2.TransferCoinsResp(extended_transaction_unsigned=extended_transaction_unsigned)

    @GrpcExceptionWrapper(qrl_pb2.PushTransactionResp)
    def PushTransaction(self, request: qrl_pb2.PushTransactionReq, context) -> qrl_pb2.PushTransactionResp:
        logger.debug("[PublicAPI] PushTransaction")
        tx = Transaction.from_pbdata(request.transaction_signed)
        tx.update_txhash()

        answer = qrl_pb2.PushTransactionResp()

        try:
            # FIXME: Full validation takes too much time. At least verify there is a signature
            # the validation happens later in the tx pool
            if len(tx.signature) > 1000:
                self.qrlnode.submit_send_tx(tx)
                answer.error_code = qrl_pb2.PushTransactionResp.SUBMITTED
                answer.tx_hash = tx.txhash
            else:
                answer.error_code = qrl_pb2.PushTransactionResp.VALIDATION_FAILED

        except Exception as e:
            error_str = traceback.format_exception(None, e, e.__traceback__)
            answer.error_description = str(''.join(error_str))
            answer.error_code = qrl_pb2.PushTransactionResp.ERROR

        return answer

    @GrpcExceptionWrapper(qrl_pb2.TransferCoinsResp)
    def GetTokenTxn(self, request: qrl_pb2.TokenTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetTokenTxn")
        tx = self.qrlnode.create_token_txn(symbol=request.symbol,
                                           name=request.name,
                                           owner=request.owner,
                                           decimals=request.decimals,
                                           initial_balances=request.initial_balances,
                                           fee=request.fee,
                                           xmss_pk=request.xmss_pk,
                                           master_addr=request.master_addr)

        extended_transaction_unsigned = qrl_pb2.TransactionExtended(tx=tx.pbdata,
                                                                    addr_from=tx.addr_from,
                                                                    size=tx.size)
        return qrl_pb2.TransferCoinsResp(extended_transaction_unsigned=extended_transaction_unsigned)

    @GrpcExceptionWrapper(qrl_pb2.TransferCoinsResp)
    def GetTransferTokenTxn(self, request: qrl_pb2.TransferTokenTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetTransferTokenTxn")
        bin_token_txhash = bytes(hstr2bin(request.token_txhash.decode()))
        tx = self.qrlnode.create_transfer_token_txn(addrs_to=request.addresses_to,
                                                    token_txhash=bin_token_txhash,
                                                    amounts=request.amounts,
                                                    fee=request.fee,
                                                    xmss_pk=request.xmss_pk,
                                                    master_addr=request.master_addr)

        extended_transaction_unsigned = qrl_pb2.TransactionExtended(tx=tx.pbdata,
                                                                    addr_from=tx.addr_from,
                                                                    size=tx.size)
        return qrl_pb2.TransferCoinsResp(extended_transaction_unsigned=extended_transaction_unsigned)

    @GrpcExceptionWrapper(qrl_pb2.TransferCoinsResp)
    def GetSlaveTxn(self, request: qrl_pb2.SlaveTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetSlaveTxn")
        tx = self.qrlnode.create_slave_tx(slave_pks=request.slave_pks,
                                          access_types=request.access_types,
                                          fee=request.fee,
                                          xmss_pk=request.xmss_pk,
                                          master_addr=request.master_addr)

        extended_transaction_unsigned = qrl_pb2.TransactionExtended(tx=tx.pbdata,
                                                                    addr_from=tx.addr_from,
                                                                    size=tx.size)
        return qrl_pb2.TransferCoinsResp(extended_transaction_unsigned=extended_transaction_unsigned)

    @GrpcExceptionWrapper(qrl_pb2.TransferCoinsResp)
    def GetLatticePublicKeyTxn(self, request: qrl_pb2.LatticePublicKeyTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetLatticePublicKeyTxn")
        tx = self.qrlnode.create_lattice_public_key_txn(kyber_pk=request.kyber_pk,
                                                        dilithium_pk=request.dilithium_pk,
                                                        fee=request.fee,
                                                        xmss_pk=request.xmss_pk,
                                                        master_addr=request.master_addr)

        extended_transaction_unsigned = qrl_pb2.TransactionExtended(tx=tx.pbdata,
                                                                    addr_from=tx.addr_from,
                                                                    size=tx.size)
        return qrl_pb2.TransferCoinsResp(extended_transaction_unsigned=extended_transaction_unsigned)

    @GrpcExceptionWrapper(qrl_pb2.GetObjectResp)
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
                    answer.address_state.CopyFrom(address_state.pbdata)
                    return answer

        transaction, block_number = self.qrlnode.get_transaction(query)
        if transaction is not None:
            answer.found = True
            blockheader = None
            if block_number is not None:
                block = self.qrlnode.get_block_from_index(block_number)
                blockheader = block.blockheader.pbdata

            txextended = qrl_pb2.TransactionExtended(header=blockheader,
                                                     tx=transaction.pbdata,
                                                     addr_from=transaction.addr_from,
                                                     size=transaction.size)
            answer.transaction.CopyFrom(txextended)
            return answer

        # NOTE: This is temporary, indexes are accepted for blocks
        try:
            block = self.qrlnode.get_block_from_hash(query)
            if block is None:
                query_str = query.decode()
                query_index = int(query_str)
                block = self.qrlnode.get_block_from_index(query_index)

            answer.found = True
            block_extended = qrl_pb2.BlockExtended()
            block_extended.header.CopyFrom(block.blockheader.pbdata)
            block_extended.size = block.size
            for transaction in block.transactions:
                tx = Transaction.from_pbdata(transaction)
                extended_tx = qrl_pb2.TransactionExtended(tx=transaction,
                                                          addr_from=tx.addr_from,
                                                          size=tx.size)
                block_extended.extended_transactions.extend([extended_tx])
            answer.block_extended.CopyFrom(block_extended)
            return answer
        except Exception:
            pass

        return answer

    @GrpcExceptionWrapper(qrl_pb2.TokenDetailedList)
    def GetTokenDetailedList(self, request: qrl_pb2.Empty, context) -> qrl_pb2.TokenDetailedList:
        logger.debug("[PublicAPI] TokenDetailedList")
        token_detailed_list = self.qrlnode.get_token_detailed_list()

        return token_detailed_list

    @GrpcExceptionWrapper(qrl_pb2.GetLatestDataResp)
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
                    transaction_count.count[CODEMAP[tx.WhichOneof('transactionType')]] += 1

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
                                                         tx=tx.pbdata,
                                                         addr_from=tx.addr_from,
                                                         size=tx.size)
                result.append(txextended)

            response.transactions.extend(result)

        if all_requested or request.filter == qrl_pb2.GetLatestDataReq.TRANSACTIONS_UNCONFIRMED:
            result = []
            for tx in self.qrlnode.get_latest_transactions_unconfirmed(offset=request.offset, count=quantity):
                txextended = qrl_pb2.TransactionExtended(header=None,
                                                         tx=tx.pbdata,
                                                         addr_from=tx.addr_from,
                                                         size=tx.size)
                result.append(txextended)
            response.transactions_unconfirmed.extend(result)

        return response

    @GrpcExceptionWrapper(qrl_pb2.PushTransactionResp)
    def PushEphemeralMessage(self, request: qrl_pb2.PushEphemeralMessageReq, context) -> qrl_pb2.PushTransactionResp:
        logger.debug("[PublicAPI] PushEphemeralMessageReq")
        submitted = False

        if config.user.accept_ephemeral:
            encrypted_ephemeral_message = EncryptedEphemeralMessage(request.ephemeral_message)
            submitted = self.qrlnode.broadcast_ephemeral_message(encrypted_ephemeral_message)

        answer = qrl_pb2.PushTransactionResp()
        answer.some_response = str(submitted)
        return answer

    @GrpcExceptionWrapper(qrl_pb2.PushTransactionResp)
    def CollectEphemeralMessage(self,
                                request: qrl_pb2.CollectEphemeralMessageReq,
                                context) -> qrl_pb2.CollectEphemeralMessageResp:
        logger.debug("[PublicAPI] CollectEphemeralMessage")

        ephemeral_metadata = self.qrlnode.collect_ephemeral_message(request.msg_id)
        answer = qrl_pb2.CollectEphemeralMessageResp(ephemeral_metadata=ephemeral_metadata.pbdata)
        return answer
