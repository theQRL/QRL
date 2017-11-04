# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import jsonpickle
import simplejson as json

from qrl.core import logger


def json_print(obj):  # prettify output from JSON for export purposes
    logger.info('%s', json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False))))


def json_print_telnet(obj):
    return json.dumps(json.loads(jsonpickle.encode(obj, make_refs=False)), indent=4)
