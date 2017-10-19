# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# FIXME: This is odd...
from grpc._cython.cygrpc import StatusCode

from qrl.core import logger
from qrl.core.Transaction import Transaction
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrl_pb2
from qrl.generated.qrl_pb2_grpc import PublicAPIServicer


class APIService(PublicAPIServicer):
    # TODO: Separate the Service from the node model
    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode

    def GetKnownPeers(self, request: qrl_pb2.GetKnownPeersReq, context) -> qrl_pb2.GetKnownPeersResp:
        try:
            known_peers = qrl_pb2.KnownPeers()
            known_peers.peers.extend([qrl_pb2.Peer(ip=p) for p in self.qrlnode.peer_addresses])
            return qrl_pb2.GetKnownPeersResp(known_peers=known_peers)
        except Exception as e:
            context.set_code(StatusCode.unknown)
            context.set_details(str(e))
            return None

    def GetAddressState(self, request: qrl_pb2.GetAddressStateReq, context) -> qrl_pb2.GetAddressStateResp:
        try:
            address_state = self.qrlnode.get_address_state(request.address)
            return qrl_pb2.GetAddressStateResp(state=address_state)
        except Exception as e:
            context.set_code(StatusCode.not_found)
            context.set_details(str(e))
            return None

    def TransferCoins(self, request: qrl_pb2.TransferCoinsReq, context) -> qrl_pb2.TransferCoinsResp:
        logger.debug("[QRLNode] TransferCoins")
        try:
            tx = self.qrlnode.create_send_tx(addr_from=request.address_from,
                                             addr_to=request.address_to,
                                             amount=request.amount,
                                             fee=request.fee,
                                             xmss_pk=request.xmss_pk,
                                             xmss_ots_index=request.xmss_ots_index)

            return qrl_pb2.TransferCoinsResp(transaction_unsigned=tx.pbdata)

        except Exception as e:
            context.set_code(StatusCode.unknown)
            context.set_details(str(e))
            return None

    def PushTransaction(self, request: qrl_pb2.PushTransactionReq, context) -> qrl_pb2.PushTransactionResp:
        logger.debug("[QRLNode] PushTransaction")
        try:
            tx = Transaction.from_pbdata(request.transaction_signed)
            submitted = self.qrlnode.submit_send_tx(tx)

            # FIXME: Improve response type
            # Prepare response
            answer = qrl_pb2.PushTransactionResp()
            answer.some_response = str(submitted)
            return answer

        except Exception as e:
            context.set_code(StatusCode.unknown)
            context.set_details(str(e))
            return None
