# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import sys
from time import time
import ntplib

from qrlcore import logger

ntp_server = 'pool.ntp.org'
version = 3
times = 5
drift = None


def get_ntp_response():
    try:
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request(ntp_server, version=version)
    except Exception as e:
        logger.exception(e)
        sys.exit(0)
    return response


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
    global drift
    curr_time = drift + int(time())
    return curr_time
