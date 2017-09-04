from enum import Enum


class NState(Enum):
    unsynced = 1
    synced = 2
    syncing = 4
    forked = 3