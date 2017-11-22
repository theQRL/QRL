import threading
from time import sleep

import grpc

from qrl.core import logger
from qrl.generated import qrl_pb2
from qrl.services.PeerManager import PeerManager


class BlockChainManager(object):
    def __init__(self, node, peer_manager):
        self.node = node
        self.peer_manager = peer_manager

        self.thread = threading.Thread(target=self._synchronize_chain)
        self.thread.daemon = True
        self.thread.start()

    def _block_received(self, response_future):
        if response_future.code() == grpc.StatusCode.OK:
            logger.info("[{:20}] _block_received {}".format(response_future.pm.conn_addr, response_future.index))
            self._get_blockchain(response_future.pm, response_future.index + 1)

    def _get_blockchain(self, peer_metadata, start_index):
        req = qrl_pb2.GetBlockReq()
        req.index = start_index
        f = peer_metadata.stub.GetBlock.future(req, timeout=PeerManager.TIMEOUT_SECS)
        f.pm = peer_metadata
        f.index = start_index
        f.add_done_callback(self._block_received)

    def _synchronize_chain(self):
        while True:
            logger.info("Peers  {:4} ({:4})".format(self.peer_manager.stable_peer_count,
                                                    self.peer_manager.peer_count))

            for peer_metadata in self.peer_manager.stable_peers():
                logger.info("{:20}: {:3}".format(peer_metadata.conn_addr,
                                                 peer_metadata.node_info.block_height))

            for peer_metadata in self.peer_manager.stable_peers():
                self._get_blockchain(peer_metadata, 0)

            sleep(2)
