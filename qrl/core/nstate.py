# coding=utf-8
from enum import Enum


class NState(Enum):
    unsynced = 1
    syncing = 2
    synced = 3
    forked = 4
