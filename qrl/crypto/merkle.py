# coding=utf-8
import time
from math import ceil, log

from qrl.core import logger
from qrl.crypto.misc import sha256


class Merkle(object):
    """
    merkle tree creation
    """
    def __init__(self, base=None, verbose=0):
        if base is None:
            base = []
        self.base = base
        self.verbose = verbose
        self.tree = []
        self.num_leaves = len(self.base)
        if not self.base:
            return
        else:
            self.create_tree()
            self.route_proof()

    def route_proof(self):  # need to add in error detection..
        start_time = time.time()
        self.auth_lists = []

        if self.verbose == 1:
            logger.info('Calculating proofs: tree height %d, %d leaves', self.height, self.num_leaves)

        for y in range(self.num_leaves):
            auth_route = []
            leaf = self.tree[0][y]
            for x in range(self.height):
                if len(self.tree[x]) == 1:
                    if self.tree[x] == self.root:
                        auth_route.append(self.root)
                        self.auth_lists.append(auth_route)
                    else:
                        logger.info('Merkle route calculation failed @ root')
                else:
                    nodes = self.tree[x]
                    nodes_above = self.tree[x + 1]
                    for node in nodes:
                        if leaf != node:
                            for nodehash in nodes_above:
                                if sha256(leaf + node) == nodehash:
                                    auth_route.append((leaf, node))  # binary hash is ordered
                                    leaf = nodehash
                                elif sha256(node + leaf) == nodehash:
                                    auth_route.append((node, leaf))
                                    leaf = nodehash
                                else:
                                    pass
        elapsed_time = time.time() - start_time
        if self.verbose == 1:
            logger.info(elapsed_time)

        return

    def create_tree(self):
        num_branches = 0
        if self.num_leaves <= 2:  # catch case for which log doesn't do the job
            num_branches = 1
        elif self.num_leaves <= 512:
            num_branches = int(ceil(log(self.num_leaves, 2)))

        self.num_branches = num_branches
        self.tree.append(self.base)

        hashlayer = self.base

        temp_array = []
        for x in range(num_branches):  # iterate through each layer of the merkle tree starting with the base layer
            temp_array = []
            cycles = len(hashlayer) % 2 + len(hashlayer) / 2
            y = 0
            # FIXME: Same variable as outer loop??
            for _ in range(cycles):
                if y + 1 == len(hashlayer):
                    temp_array.append(str(hashlayer[y]))
                else:
                    temp_array.append(sha256(str(hashlayer[y]) + str(hashlayer[y + 1])))
                    y = y + 2

            self.tree.append(temp_array)
            hashlayer = temp_array

        self.root = temp_array
        self.height = len(self.tree)

        if self.verbose == 1:
            logger.info('Merkle tree created with %d leaves, %d branches', self.num_leaves, self.num_branches)

        return self.tree

    def check_item(self):
        return


def random_generic(func, signatures=4, verbose=False):
    # winternitz merkle signature scheme
    begin = time.time()
    data = []
    pubhashes = []

    for x in range(signatures):
        data.append(func(signatures, index=x, verbose=verbose))

    for i in range(len(data)):
        pubhashes.append(data[i].pubhash)

    a = Merkle(base=pubhashes, verbose=verbose)

    for y in range(signatures):
        data[y].merkle_root = ''.join(a.root)
        data[y].merkle_path = a.auth_lists[y]
        data[y].merkle_obj = a

    if verbose:
        logger.info('Total MSS time = %s', str(time.time() - begin))

    return data  # array of wots classes full of data.. and a class full of merkle
