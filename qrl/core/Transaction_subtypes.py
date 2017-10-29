# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.generated import qrl_pb2

TX_SUBTYPE_TX = qrl_pb2.Transaction.TRANSFER
TX_SUBTYPE_STAKE = qrl_pb2.Transaction.STAKE
TX_SUBTYPE_DESTAKE = qrl_pb2.Transaction.DESTAKE
TX_SUBTYPE_COINBASE = qrl_pb2.Transaction.COINBASE
TX_SUBTYPE_LATTICE = qrl_pb2.Transaction.LATTICE
TX_SUBTYPE_DUPLICATE = qrl_pb2.Transaction.DUPLICATE