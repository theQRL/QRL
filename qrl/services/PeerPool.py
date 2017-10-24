import threading
from time import time, sleep

import grpc

from qrl.generated import qrl_pb2


class PeerPool(object):
    TIMEOUT_SECS = 3
    DISCOVERY_TIME_SECS = 3
    STABILITY_TIME_SECS = 5

    def __init__(self):
        self._p2p_stubs = dict()
        self._p2p_time = dict()

        self._lock = threading.Lock()
        self.thread = threading.Thread(target=self._maintain_peers)
        self.thread.daemon = True
        self.thread.start()
        # TODO: Create a bloom filter (as a black list) to avoid frequent reconnections

    def add(self, addr_list):
        with self._lock:
            # FIXME: Limit amount of connections
            for peer_ip in addr_list:
                peer_conn = '{}:9009'.format(peer_ip)
                if peer_conn not in self._p2p_stubs:
                    channel = grpc.insecure_channel(peer_conn)
                    self._p2p_stubs[peer_conn] = qrl_pb2.P2PNodeStub(channel)
                    self._p2p_time[peer_conn] = time()

    def remove(self, conn_list):
        with self._lock:
            for peer_conn in conn_list:
                self._p2p_stubs.pop(peer_conn, None)
                self._p2p_time.pop(peer_conn, None)

    def recycle(self):
        with self._lock:
            # FIXME: Flush very old connections to promote change, swap peers, etc. Use hash logic
            pass

    def stable_stubs(self)->list:
        with self._lock:
            # FIXME: Improve look up
            tmp = []
            for k, v in self._p2p_time.items():
                if time() - v > PeerPool.STABILITY_TIME_SECS:
                    tmp.append(self._p2p_stubs[k])
        return tmp

    def _all_stubs(self):
        # FIXME: Improve this. Make a temporary copy for now
        with self._lock:
            tmp = list(self._p2p_stubs.values())
        return iter(tmp)

    def _maintain_peers(self):
        # TODO: Keep peer pool up to date, stats, etc
        # TODO: Improve recycling logic
        while True:
            for stub in self._all_stubs():
                try:
                    def add_peers_callback(f):
                        if f.code() == grpc.StatusCode.OK:
                            peer_list = (peer.ip for peer in f.result().known_peers.peers)
                            # TODO: Make a second call to check version or remove node
                            self.add(peer_list)
                        else:
                            # FIXME: Open PR to expose this or keep a relation between future/peer
                            self.remove([f._call.peer().decode()])

                    stub.GetKnownPeers.future(qrl_pb2.GetKnownPeersReq(),
                                              timeout=PeerPool.TIMEOUT_SECS).add_done_callback(add_peers_callback)

                except grpc.RpcError as e:
                    pass

            print("Peers  {} ({})".format(len(self.stable_stubs()), len(self._p2p_stubs)))
            sleep(PeerPool.DISCOVERY_TIME_SECS)
