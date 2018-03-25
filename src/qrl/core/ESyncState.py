# coding=utf-8
from enum import Enum


class ESyncState(Enum):
    unknown = 0
    unsynced = 1
    syncing = 2
    synced = 3
    forked = 4
