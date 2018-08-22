# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import traceback
from statistics import variance, mean

from pyqrllib.pyqrllib import hstr2bin, QRLHelper, QRLDescriptor

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.qrlnode import QRLNode
from qrl.core.txs.Transaction import Transaction, CODEMAP
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
        return qrl_pb2.GetNodeStateResp(info=self.qrlnode.get_node_info())

    @GrpcExceptionWrapper(qrl_pb2.GetKnownPeersResp)
    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        response = qrl_pb2.GetKnownPeersResp()
        response.node_info.CopyFrom(self.qrlnode.get_node_info())
        response.known_peers.extend([qrl_pb2.Peer(ip=p) for p in self.qrlnode.peer_manager.known_peer_addresses])

        return response

    @GrpcExceptionWrapper(qrl_pb2.GetStatsResp)
    def GetStats(self, request: qrl_pb2.GetStatsReq, context) -> qrl_pb2.GetStatsResp:
        response = qrl_pb2.GetStatsResp()
        response.node_info.CopyFrom(self.qrlnode.get_node_info())

        response.epoch = self.qrlnode.epoch
        response.uptime_network = self.qrlnode.uptime_network
        response.block_last_reward = self.qrlnode.block_last_reward
        response.coins_total_supply = int(self.qrlnode.coin_supply_max)
        response.coins_emitted = int(self.qrlnode.coin_supply)

        response.block_time_mean = 0
        response.block_time_sd = 0

        if request.include_timeseries:
            tmp = list(self.qrlnode.get_block_timeseries(config.dev.block_timeseries_size))
            response.block_timeseries.extend(tmp)
            if len(tmp) > 2:
                vals = [v.time_last for v in tmp[1:]]
                response.block_time_mean = int(mean(vals))
                response.block_time_sd = int(variance(vals) ** 0.5)
        return response

    @GrpcExceptionWrapper(qrl_pb2.ParseAddressResp)
    def ParseAddress(self, request: qrl_pb2.ParseAddressReq, context) -> qrl_pb2.ParseAddressResp:
        response = qrl_pb2.ParseAddressResp()
        response.is_valid = QRLHelper.addressIsValid(request.address)
        descriptor = QRLDescriptor.fromBytes(request.address[:3])
        hf_dict = {0: 'SHA2-256', 1: 'SHAKE-128', 2: 'SHAKE-256', 3: 'RESERVED'}
        ss_dict = {0: 'XMSS', 1: 'XMSS-MT'}
        af_dict = {0: 'SHA2-256', 1: 'RESERVED', 3: 'RESERVED'}
        response.desc.hash_function = hf_dict[descriptor.getHashFunction()]
        response.desc.tree_height = descriptor.getHeight()
        response.desc.signatures = 2**response.desc.tree_height
        response.desc.signature_scheme = ss_dict[descriptor.getSignatureType()]
        response.desc.address_format = af_dict[descriptor.getAddrFormatType()]
        return response

    @GrpcExceptionWrapper(qrl_pb2.GetAddressStateResp)
    def GetAddressState(self, request: qrl_pb2.GetAddressStateReq, context) -> qrl_pb2.GetAddressStateResp:
        address_state = self.qrlnode.get_address_state(request.address)
        if request.exclude_ots_bitfield:
            del address_state.pbdata.ots_bitfield[:]
        if request.exclude_transaction_hashes:
            del address_state.pbdata.transaction_hashes[:]
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
        answer = qrl_pb2.PushTransactionResp()

        try:
            tx = Transaction.from_pbdata(request.transaction_signed)
            tx.update_txhash()

            # FIXME: Full validation takes too much time. At least verify there is a signature
            # the validation happens later in the tx pool
            if len(tx.signature) > 1000:
                self.qrlnode.submit_send_tx(tx)
                answer.error_code = qrl_pb2.PushTransactionResp.SUBMITTED
                answer.tx_hash = tx.txhash
            else:
                answer.error_description = 'Signature too short'
                answer.error_code = qrl_pb2.PushTransactionResp.VALIDATION_FAILED

        except Exception as e:
            error_str = traceback.format_exception(None, e, e.__traceback__)
            answer.error_description = str(''.join(error_str))
            answer.error_code = qrl_pb2.PushTransactionResp.ERROR

        return answer

    @GrpcExceptionWrapper(qrl_pb2.TransferCoinsResp)
    def GetMessageTxn(self, request: qrl_pb2.TokenTxnReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[PublicAPI] GetMessageTxn")
        tx = self.qrlnode.create_message_txn(message_hash=request.message,
                                             fee=request.fee,
                                             xmss_pk=request.xmss_pk,
                                             master_addr=request.master_addr)

        extended_transaction_unsigned = qrl_pb2.TransactionExtended(tx=tx.pbdata,
                                                                    addr_from=tx.addr_from,
                                                                    size=tx.size)
        return qrl_pb2.TransferCoinsResp(extended_transaction_unsigned=extended_transaction_unsigned)

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

    @GrpcExceptionWrapper(qrl_pb2.GetObjectResp)
    def GetObject(self, request: qrl_pb2.GetObjectReq, context) -> qrl_pb2.GetObjectResp:
        logger.debug("[PublicAPI] GetObject")
        answer = qrl_pb2.GetObjectResp()
        answer.found = False

        # FIXME: We need a unified way to access and validate data.
        query = bytes(request.query)  # query will be as a string, if Q is detected convert, etc.

        try:
            if AddressState.address_is_valid(query):
                if self.qrlnode.get_address_is_used(query):
                    address_state = self.qrlnode.get_address_state(query)
                    if address_state is not None:
                        answer.found = True
                        answer.address_state.CopyFrom(address_state.pbdata)
                        return answer
        except ValueError:
            pass

        transaction_block_number = self.qrlnode.get_transaction(query)
        transaction = None
        blockheader = None
        if transaction_block_number:
            transaction, block_number = transaction_block_number
            answer.found = True
            block = self.qrlnode.get_block_from_index(block_number)
            blockheader = block.blockheader.pbdata
            timestamp = block.blockheader.timestamp
        else:
            transaction_timestamp = self.qrlnode.get_unconfirmed_transaction(query)
            if transaction_timestamp:
                transaction, timestamp = transaction_timestamp
                answer.found = True

        if transaction:
            txextended = qrl_pb2.TransactionExtended(header=blockheader,
                                                     tx=transaction.pbdata,
                                                     addr_from=transaction.addr_from,
                                                     size=transaction.size,
                                                     timestamp_seconds=timestamp)
            answer.transaction.CopyFrom(txextended)
            return answer

        # NOTE: This is temporary, indexes are accepted for blocks
        try:
            block = self.qrlnode.get_block_from_hash(query)
            if block is None:
                query_str = query.decode()
                query_index = int(query_str)
                block = self.qrlnode.get_block_from_index(query_index)
                if not block:
                    return answer

            answer.found = True
            block_extended = qrl_pb2.BlockExtended()
            block_extended.header.CopyFrom(block.blockheader.pbdata)
            block_extended.size = block.size
            for transaction in block.transactions:
                tx = Transaction.from_pbdata(transaction)
                extended_tx = qrl_pb2.TransactionExtended(tx=transaction,
                                                          addr_from=tx.addr_from,
                                                          size=tx.size,
                                                          timestamp_seconds=block.blockheader.timestamp)
                block_extended.extended_transactions.extend([extended_tx])
            answer.block_extended.CopyFrom(block_extended)
            return answer
        except Exception:
            pass

        return answer

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
            for tx_info in self.qrlnode.get_latest_transactions_unconfirmed(offset=request.offset, count=quantity):
                tx = tx_info.transaction
                txextended = qrl_pb2.TransactionExtended(header=None,
                                                         tx=tx.pbdata,
                                                         addr_from=tx.addr_from,
                                                         size=tx.size,
                                                         timestamp_seconds=tx_info.timestamp)
                result.append(txextended)
            response.transactions_unconfirmed.extend(result)

        return response

    @GrpcExceptionWrapper(qrl_pb2.GetTransactionsByAddressResp)
    def GetTransactionsByAddress(self,
                                 request: qrl_pb2.GetTransactionsByAddressReq,
                                 context) -> qrl_pb2.GetTransactionsByAddressResp:
        logger.debug("[PublicAPI] GetTransactionsByAddress")
        response = qrl_pb2.GetTransactionsByAddressResp()
        mini_transactions, balance = self.qrlnode.get_transactions_by_address(request.address)
        response.mini_transactions.extend(mini_transactions)
        response.balance = balance
        return response

    @GrpcExceptionWrapper(qrl_pb2.GetTransactionResp)
    def GetTransaction(self, request: qrl_pb2.GetTransactionReq, context) -> qrl_pb2.GetTransactionResp:
        logger.debug("[PublicAPI] GetTransaction")
        response = qrl_pb2.GetTransactionResp()
        tx_blocknumber = self.qrlnode.get_transaction(request.tx_hash)
        if tx_blocknumber:
            response.tx.MergeFrom(tx_blocknumber[0].pbdata)
            response.confirmations = self.qrlnode.block_height - tx_blocknumber[1] + 1
            response.block_number = tx_blocknumber[1]
            response.block_header_hash = self.qrlnode.get_block_header_hash_by_number(tx_blocknumber[1])
        else:
            tx_timestamp = self.qrlnode.get_unconfirmed_transaction(request.tx_hash)
            if tx_timestamp:
                response.tx.MergeFrom(tx_timestamp[0].pbdata)
                response.confirmations = 0

        return response

    @GrpcExceptionWrapper(qrl_pb2.GetBalanceResp)
    def GetBalance(self, request: qrl_pb2.GetBalanceReq, context) -> qrl_pb2.GetBalanceResp:
        logger.debug("[PublicAPI] GetBalance")
        address_state = self.qrlnode.get_address_state(request.address)
        response = qrl_pb2.GetBalanceResp(balance=address_state.balance)
        return response

    @GrpcExceptionWrapper(qrl_pb2.GetOTSResp)
    def GetOTS(self, request: qrl_pb2.GetOTSReq, context) -> qrl_pb2.GetOTSResp:
        logger.debug("[PublicAPI] GetOTS")
        address_state = self.qrlnode.get_address_state(request.address)
        response = qrl_pb2.GetOTSResp(ots_bitfield=address_state.ots_bitfield,
                                      next_unused_ots_index=address_state.get_unused_ots_index())
        return response

    @GrpcExceptionWrapper(qrl_pb2.GetHeightResp)
    def GetHeight(self, request: qrl_pb2.GetHeightReq, context) -> qrl_pb2.GetHeightResp:
        logger.debug("[PublicAPI] GetHeight")
        return qrl_pb2.GetHeightResp(height=self.qrlnode.block_height)

    @GrpcExceptionWrapper(qrl_pb2.GetBlockResp)
    def GetBlock(self, request: qrl_pb2.GetBlockReq, context) -> qrl_pb2.GetBlockResp:
        logger.debug("[PublicAPI] GetBlock")
        block = self.qrlnode.get_block_from_hash(request.header_hash)
        if block:
            return qrl_pb2.GetBlockResp(block=block.pbdata)
        return qrl_pb2.GetBlockResp()

    @GrpcExceptionWrapper(qrl_pb2.GetBlockByNumberResp)
    def GetBlockByNumber(self, request: qrl_pb2.GetBlockByNumberReq, context) -> qrl_pb2.GetBlockByNumberResp:
        logger.debug("[PublicAPI] GetBlockFromNumber")
        block = self.qrlnode.get_block_from_index(request.block_number)
        if block:
            return qrl_pb2.GetBlockByNumberResp(block=block.pbdata)
        return qrl_pb2.GetBlockByNumberResp()
