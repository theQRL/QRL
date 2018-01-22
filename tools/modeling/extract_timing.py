import os

from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from pyqryptonight.pyqryptonight import PoWHelper, StringToUInt256, UInt256ToString

persistent_state = State()
chain_manager = ChainManager(state=persistent_state)
chain_manager.load(GenesisBlock())

ph = PoWHelper()
difficulty = StringToUInt256('5000')
delta = 0

filename = os.path.expanduser("~/crypto/qryptonight/modeling/blockdata.csv")

with open(filename, 'w') as f:
    f.write("i,timestamp,prev_timestamp,delta,difficulty,boundary\n")
    prev_timestamp = None
    for i in range(chain_manager.height):
        block = chain_manager.get_block_by_number(i)

        if i == 0:
            prev_timestamp = block.blockheader.timestamp
            continue

        boundary = ph.getBoundary(difficulty)
        delta = block.blockheader.timestamp - prev_timestamp

        outs = "{},{},{},{},{},{}\n".format(i,
                                            block.blockheader.timestamp,
                                            prev_timestamp,
                                            delta,
                                            UInt256ToString(difficulty),
                                            UInt256ToString(boundary))

        f.write(outs)

        difficulty = ph.getDifficulty(block.blockheader.timestamp, prev_timestamp, difficulty)
        difficulty = StringToUInt256(str(max(2, int(UInt256ToString(difficulty)))))
        prev_timestamp = block.blockheader.timestamp
