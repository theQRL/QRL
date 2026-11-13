# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import re
from typing import Optional

import grpc
from grpc import StatusCode

from qrl.core.misc import logger
from qrl.generated import qrl_pb2


class GrpcExceptionWrapper(object):
    def __init__(self, response_type, state_code=StatusCode.UNKNOWN):
        self.response_type = response_type
        self.state_code = state_code

    def _set_context(self, context, exception, code=None):
        if context is not None:
            if code is None:
                context.set_code(self.state_code)
            else:
                context.set_code(code)

            context.set_details(str(exception))

    def __call__(self, f):
        def wrap_f(caller_self, request, context):
            try:
                return f(caller_self, request, context)
            except ValueError as e:
                self._set_context(context, e, StatusCode.INVALID_ARGUMENT)
                logger.info(str(e))
                return self.response_type()
            except Exception as e:
                self._set_context(context, e)
                logger.exception(e)
                return self.response_type()

        return wrap_f


_OTS_RETRY_RE = re.compile(r'OTS scan limit reached; retry from index (\d+)')


def request_unused_ots_index(public_stub, address: bytes, start: int = 0) -> Optional[int]:
    """
    Asks a node for the next unused OTS index at or above `start` via GetOTS.

    The node bounds each scan and answers INVALID_ARGUMENT with a retry index
    when it reaches the limit; that is not key exhaustion, so continue from
    the retry index. Returns None only when the node reports no unused key.
    """
    while True:
        try:
            response = public_stub.GetOTS(request=qrl_pb2.GetOTSReq(address=address,
                                                                    page_from=0,
                                                                    page_count=0,
                                                                    unused_ots_index_from=start))
        except grpc.RpcError as e:
            match = None
            if e.code() == StatusCode.INVALID_ARGUMENT:
                match = _OTS_RETRY_RE.search(e.details() or '')
            if match is None or int(match.group(1)) <= start:
                raise
            start = int(match.group(1))
            continue
        if not response.unused_ots_index_found:
            return None
        if response.next_unused_ots_index < start:
            raise ValueError('GetOTS returned an index below the requested start')
        return response.next_unused_ots_index
