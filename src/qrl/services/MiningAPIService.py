# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from grpc import StatusCode

from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.qrlnode import QRLNode
from qrl.generated import qrlmining_pb2
from qrl.generated.qrlmining_pb2_grpc import MiningAPIServicer
from qrl.services.grpcHelper import GrpcExceptionWrapper


class MiningAPIService(MiningAPIServicer):
    MAX_REQUEST_QUANTITY = 100

    def __init__(self, qrlnode: QRLNode):
        self.qrlnode = qrlnode

    @GrpcExceptionWrapper(qrlmining_pb2.GetBlockMiningCompatibleResp, StatusCode.UNKNOWN)
    def GetBlockMiningCompatible(self,
                                 request: qrlmining_pb2.GetBlockMiningCompatibleReq,
                                 context) -> qrlmining_pb2.GetBlockMiningCompatibleResp:

        blockheader, block_metadata = self.qrlnode.get_blockheader_and_metadata(request.height)

        response = qrlmining_pb2.GetBlockMiningCompatibleResp()
        if blockheader is not None and block_metadata is not None:
            response = qrlmining_pb2.GetBlockMiningCompatibleResp(
                blockheader=blockheader.pbdata,
                blockmetadata=block_metadata.pbdata)

        return response

    @GrpcExceptionWrapper(qrlmining_pb2.GetLastBlockHeaderResp, StatusCode.UNKNOWN)
    def GetLastBlockHeader(self,
                           request: qrlmining_pb2.GetLastBlockHeaderReq,
                           context) -> qrlmining_pb2.GetLastBlockHeaderResp:
        response = qrlmining_pb2.GetLastBlockHeaderResp()

        blockheader, block_metadata = self.qrlnode.get_blockheader_and_metadata(request.height)

        response.difficulty = int(bin2hstr(block_metadata.block_difficulty), 16)
        response.height = self.qrlnode.block_height
        response.timestamp = blockheader.timestamp
        response.reward = blockheader.block_reward + blockheader.fee_reward
        response.hash = bin2hstr(blockheader.headerhash)
        response.depth = self.qrlnode.block_height - blockheader.block_number

        return response

    @GrpcExceptionWrapper(qrlmining_pb2.GetBlockToMineResp, StatusCode.UNKNOWN)
    def GetBlockToMine(self,
                       request: qrlmining_pb2.GetBlockToMineReq,
                       context) -> qrlmining_pb2.GetBlockToMineResp:

        response = qrlmining_pb2.GetBlockToMineResp()

        blocktemplate_blob_and_difficulty = self.qrlnode.get_block_to_mine(request.wallet_address)

        if blocktemplate_blob_and_difficulty:
            response.blocktemplate_blob = blocktemplate_blob_and_difficulty[0]
            response.difficulty = blocktemplate_blob_and_difficulty[1]
            response.height = self.qrlnode.block_height + 1
            response.reserved_offset = config.dev.extra_nonce_offset

        return response

    @GrpcExceptionWrapper(qrlmining_pb2.GetBlockToMineResp, StatusCode.UNKNOWN)
    def SubmitMinedBlock(self,
                         request: qrlmining_pb2.SubmitMinedBlockReq,
                         context) -> qrlmining_pb2.SubmitMinedBlockResp:
        response = qrlmining_pb2.SubmitMinedBlockResp()

        response.error = not self.qrlnode.submit_mined_block(request.blob)

        return response
