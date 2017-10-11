# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import sys
from time import time

from ntplib import NTPClient

from qrl.core import logger

ntp_servers = ['pool.ntp.org', 'ntp.ubuntu.com']
NTP_VERSION = 3
NTP_RETRIES = 6
drift = None


def get_ntp_response():
    for retry in range(NTP_RETRIES):
        ntp_server = ntp_servers[retry % len(ntp_servers)]
        try:
            ntp_client = NTPClient()
            response = ntp_client.request(ntp_server, version=NTP_VERSION)
        except Exception as e:
            logger.warning(e)
            continue
        return response

    # FIXME: Provide some proper clean before exiting
    logger.fatal("Could not contact NTP servers after %d retries", NTP_RETRIES)
    sys.exit(-1)


def getNTP():
    ntp_timestamp = 0
    response = get_ntp_response()
    if response:
        ntp_timestamp = int(response.tx_time)
    return ntp_timestamp


def setDrift():
    global drift
    response = get_ntp_response()
    if not response:
        return response
    drift = response.offset


def getTime():
    """
    :return:
    :rtype: float

    >>> getTime() is not None
    True
    """
    global drift

    if drift is None:
        setDrift()

    curr_time = drift + int(time())
    return curr_time
