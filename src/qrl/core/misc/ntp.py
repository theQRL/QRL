# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import sys
from time import time

from ntplib import NTPClient

from qrl.core import config
from qrl.core.misc import logger

NTP_VERSION = 3
NTP_RETRIES = 6
drift = None
last_refresh = 0


def get_ntp_response():
    for retry in range(NTP_RETRIES):
        ntp_server = config.user.ntp_servers[retry % len(config.user.ntp_servers)]
        try:
            ntp_client = NTPClient()
            response = ntp_client.request(ntp_server, version=NTP_VERSION, timeout=config.user.ntp_request_timeout)
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
    global drift, last_refresh
    response = get_ntp_response()
    if not response:
        return response
    drift = response.offset
    last_refresh = drift + int(time())


def getTime():
    """
    :return:
    :rtype: int

    >>> getTime() is not None
    True
    """
    global drift, last_refresh

    if drift is None:
        setDrift()

    curr_time = int(drift + time())

    if curr_time - last_refresh > config.user.ntp_refresh:
        setDrift()

    return curr_time
