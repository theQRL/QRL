# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from pyqrllib.pyqrllib import bin2hstr
from qrl.generated import qrlwallet_pb2
from qrl.generated.qrlwallet_pb2_grpc import WalletAPIServicer
from qrl.services.grpcHelper import GrpcExceptionWrapper


class WalletAPIService(WalletAPIServicer):
    MAX_REQUEST_QUANTITY = 100

    # TODO: Separate the Service from the node model
    def __init__(self, walletd):
        self._walletd = walletd

    @GrpcExceptionWrapper(qrlwallet_pb2.AddNewAddressResp)
    def AddNewAddress(self, request: qrlwallet_pb2.AddNewAddressReq, context) -> qrlwallet_pb2.AddNewAddressResp:
        resp = qrlwallet_pb2.AddNewAddressResp()
        try:
            resp.address = self._walletd.add_new_address(request.height, request.hash_function.lower())
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.AddNewAddressResp)
    def AddNewAddressWithSlaves(self, request: qrlwallet_pb2.AddNewAddressWithSlavesReq, context) -> qrlwallet_pb2.AddNewAddressResp:
        resp = qrlwallet_pb2.AddNewAddressResp()
        try:
            resp.address = self._walletd.add_new_address_with_slaves(request.height,
                                                                     request.number_of_slaves,
                                                                     request.hash_function.lower())
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.AddAddressFromSeedResp)
    def AddAddressFromSeed(self, request: qrlwallet_pb2.AddAddressFromSeedReq, context) -> qrlwallet_pb2.AddAddressFromSeedResp:
        resp = qrlwallet_pb2.AddAddressFromSeedResp()
        try:
            resp.address = self._walletd.add_address_from_seed(seed=request.seed)
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.ListAddressesResp)
    def ListAddresses(self, request: qrlwallet_pb2.ListAddressesReq, context) -> qrlwallet_pb2.ListAddressesResp:
        resp = qrlwallet_pb2.ListAddressesResp()
        try:
            resp.addresses.extend(self._walletd.list_address())
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RemoveAddressResp)
    def RemoveAddress(self, request: qrlwallet_pb2.RemoveAddressReq, context) -> qrlwallet_pb2.RemoveAddressResp:
        resp = qrlwallet_pb2.RemoveAddressResp()
        try:
            if not self._walletd.remove_address(request.address):
                resp.code = 1
                resp.error = "No such address found"
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.ValidAddressResp)
    def IsValidAddress(self, request: qrlwallet_pb2.ValidAddressReq, context) -> qrlwallet_pb2.ValidAddressResp:
        resp = qrlwallet_pb2.ValidAddressResp()
        try:
            if not self._walletd.validate_address(request.address):
                resp.code = 1
                resp.error = "Invalid QRL Address"
                resp.valid = "False"
            else:
                resp.valid = "True"
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.GetRecoverySeedsResp)
    def GetRecoverySeeds(self, request: qrlwallet_pb2.GetRecoverySeedsReq, context) -> qrlwallet_pb2.GetRecoverySeedsResp:
        resp = qrlwallet_pb2.GetRecoverySeedsResp()
        try:
            resp.hexseed, resp.mnemonic = self._walletd.get_recovery_seeds(request.address)
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.GetWalletInfoResp)
    def GetWalletInfo(self, request: qrlwallet_pb2.GetWalletInfoReq, context) -> qrlwallet_pb2.GetWalletInfoResp:
        resp = qrlwallet_pb2.GetWalletInfoResp()
        try:
            resp.version, resp.address_count, resp.is_encrypted = self._walletd.get_wallet_info()
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayTransferTxn(self, request: qrlwallet_pb2.RelayTransferTxnReq, context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_transfer_txn(request.addresses_to,
                                                               request.amounts,
                                                               request.fee,
                                                               request.master_address,
                                                               request.signer_address,
                                                               request.ots_index))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayTransferTxnBySlave(self,
                                request: qrlwallet_pb2.RelayTransferTxnBySlaveReq,
                                context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_transfer_txn_by_slave(request.addresses_to,
                                                                        request.amounts,
                                                                        request.fee,
                                                                        request.master_address))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayMessageTxn(self, request: qrlwallet_pb2.RelayMessageTxnReq, context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_message_txn(request.message,
                                                              request.fee,
                                                              request.master_address,
                                                              request.signer_address,
                                                              request.ots_index))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayMessageTxnBySlave(self,
                               request: qrlwallet_pb2.RelayMessageTxnBySlaveReq,
                               context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_message_txn_by_slave(request.message,
                                                                       request.fee,
                                                                       request.master_address))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayTokenTxn(self, request: qrlwallet_pb2.RelayTokenTxnReq, context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_token_txn(request.symbol,
                                                            request.name,
                                                            request.owner,
                                                            request.decimals,
                                                            request.addresses,
                                                            request.amounts,
                                                            request.fee,
                                                            request.master_address,
                                                            request.signer_address,
                                                            request.ots_index))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayTokenTxnBySlave(self,
                             request: qrlwallet_pb2.RelayTokenTxnBySlaveReq,
                             context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_token_txn_by_slave(request.symbol,
                                                                     request.name,
                                                                     request.owner,
                                                                     request.decimals,
                                                                     request.addresses,
                                                                     request.amounts,
                                                                     request.fee,
                                                                     request.master_address))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayTransferTokenTxn(self, request: qrlwallet_pb2.RelayTransferTokenTxnReq, context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_transfer_token_txn(request.addresses_to,
                                                                     request.amounts,
                                                                     request.token_txhash,
                                                                     request.fee,
                                                                     request.master_address,
                                                                     request.signer_address,
                                                                     request.ots_index))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelayTransferTokenTxnBySlave(self,
                                     request: qrlwallet_pb2.RelayTransferTokenTxnBySlaveReq,
                                     context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_transfer_token_txn_by_slave(request.addresses_to,
                                                                              request.amounts,
                                                                              request.token_txhash,
                                                                              request.fee,
                                                                              request.master_address))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelaySlaveTxn(self, request: qrlwallet_pb2.RelaySlaveTxnReq, context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_slave_txn(request.slave_pks,
                                                            request.access_types,
                                                            request.fee,
                                                            request.master_address,
                                                            request.signer_address,
                                                            request.ots_index))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.RelayTxnResp)
    def RelaySlaveTxnBySlave(self, request: qrlwallet_pb2.RelaySlaveTxnBySlaveReq, context) -> qrlwallet_pb2.RelayTxnResp:
        resp = qrlwallet_pb2.RelayTxnResp()
        try:
            resp.tx.MergeFrom(self._walletd.relay_slave_txn_by_slave(request.slave_pks,
                                                                     request.access_types,
                                                                     request.fee,
                                                                     request.master_address))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.EncryptWalletResp)
    def EncryptWallet(self, request: qrlwallet_pb2.EncryptWalletReq, context) -> qrlwallet_pb2.EncryptWalletResp:
        resp = qrlwallet_pb2.EncryptWalletResp()
        try:
            self._walletd.encrypt_wallet(request.passphrase)
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.LockWalletResp)
    def LockWallet(self, request: qrlwallet_pb2.LockWalletReq, context) -> qrlwallet_pb2.LockWalletResp:
        resp = qrlwallet_pb2.LockWalletResp()
        try:
            self._walletd.lock_wallet()
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.UnlockWalletResp)
    def UnlockWallet(self, request: qrlwallet_pb2.UnlockWalletReq, context) -> qrlwallet_pb2.UnlockWalletResp:
        resp = qrlwallet_pb2.UnlockWalletResp()
        try:
            self._walletd.unlock_wallet(request.passphrase)
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.ChangePassphraseResp)
    def ChangePassphrase(self,
                         request: qrlwallet_pb2.ChangePassphraseReq,
                         context) -> qrlwallet_pb2.ChangePassphraseResp:
        resp = qrlwallet_pb2.ChangePassphraseResp()
        try:
            self._walletd.change_passphrase(request.oldPassphrase, request.newPassphrase)
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.TransactionsByAddressResp)
    def GetTransactionsByAddress(self,
                                 request: qrlwallet_pb2.TransactionsByAddressReq,
                                 context) -> qrlwallet_pb2.TransactionsByAddressResp:
        resp = qrlwallet_pb2.TransactionsByAddressResp()
        try:
            mini_transactions, balance = self._walletd.get_mini_transactions_by_address(qaddress=request.address,
                                                                                        item_per_page=1000000,
                                                                                        page_number=1)
            resp.mini_transactions.extend(mini_transactions)
            resp.balance = balance
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.TransactionResp)
    def GetTransaction(self, request: qrlwallet_pb2.TransactionReq, context) -> qrlwallet_pb2.TransactionResp:
        resp = qrlwallet_pb2.TransactionResp()
        try:
            tx, confirmations, block_number, block_header_hash = self._walletd.get_transaction(request.tx_hash)
            resp.tx.MergeFrom(tx)
            resp.confirmations = confirmations
            resp.block_number = block_number
            if block_header_hash:
                resp.block_header_hash = block_header_hash
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.BalanceResp)
    def GetBalance(self, request: qrlwallet_pb2.BalanceReq, context) -> qrlwallet_pb2.BalanceResp:
        resp = qrlwallet_pb2.BalanceResp()
        try:
            resp.balance = str(self._walletd.get_balance(request.address))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.TotalBalanceResp)
    def GetTotalBalance(self, request: qrlwallet_pb2.TotalBalanceReq, context) -> qrlwallet_pb2.TotalBalanceResp:
        resp = qrlwallet_pb2.TotalBalanceResp()
        try:
            resp.balance = str(self._walletd.get_total_balance())
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.OTSResp)
    def GetOTS(self, request: qrlwallet_pb2.OTSReq, context) -> qrlwallet_pb2.OTSResp:
        try:
            ots_bitfield_by_page, next_unused_ots_index, unused_ots_index_found = self._walletd.get_ots(request.address)
            resp = qrlwallet_pb2.OTSResp(ots_bitfield_by_page=ots_bitfield_by_page,
                                         next_unused_ots_index=next_unused_ots_index,
                                         unused_ots_index_found=unused_ots_index_found)
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.HeightResp)
    def GetHeight(self, request: qrlwallet_pb2.HeightReq, context) -> qrlwallet_pb2.HeightResp:
        resp = qrlwallet_pb2.HeightResp()
        try:
            resp.height = self._walletd.get_height()
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.BlockResp)
    def GetBlock(self, request: qrlwallet_pb2.BlockReq, context) -> qrlwallet_pb2.BlockResp:
        resp = qrlwallet_pb2.BlockResp()
        try:
            resp.block.MergeFrom(self._walletd.get_block(request.header_hash))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.BlockResp)
    def GetBlockByNumber(self, request: qrlwallet_pb2.BlockByNumberReq, context) -> qrlwallet_pb2.BlockResp:
        resp = qrlwallet_pb2.BlockResp()
        try:
            resp.block.MergeFrom(self._walletd.get_block_by_number(request.block_number))
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.AddressFromPKResp)
    def GetAddressFromPK(self, request: qrlwallet_pb2.AddressFromPKReq, context) -> qrlwallet_pb2.AddressFromPKResp:
        resp = qrlwallet_pb2.AddressFromPKResp()
        try:
            resp.address = self._walletd.get_address_from_pk(request.pk)
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp

    @GrpcExceptionWrapper(qrlwallet_pb2.NodeInfoResp)
    def GetNodeInfo(self, request: qrlwallet_pb2.NodeInfoReq, context) -> qrlwallet_pb2.NodeInfoResp:
        resp = qrlwallet_pb2.NodeInfoResp()
        try:
            node_info = self._walletd.get_node_info()

            resp.version = node_info.info.version
            resp.num_connections = str(node_info.info.num_connections)
            resp.num_known_peers = str(node_info.info.num_known_peers)
            resp.uptime = node_info.info.uptime
            resp.block_height = node_info.info.block_height
            resp.block_last_hash = bin2hstr(node_info.info.block_last_hash)
            resp.network_id = node_info.info.network_id
        except Exception as e:
            resp.code = 1
            resp.error = str(e)

        return resp
