# coding=utf-8
"""
This file provide temporary functions that will later be ported to C++
"""
from pyqrllib.pyqrllib import ucharVector


def get_seed():
    # FIXME: Provide a proper seed based on urandom
    return ucharVector(32, 0)
