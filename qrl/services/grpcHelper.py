# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core import logger


class grpc_exception_wrapper(object):
    def __init__(self, response_type, state_code):
        self.response_type = response_type
        self.state_code = state_code

    def _set_context(self, context, exception):
        if context is not None:
            context.set_code(self.state_code)
            context.set_details(str(exception))

    def __call__(self, f):
        def wrap_f(caller_self, request, context):
            try:
                return f(caller_self, request, context)
            except ValueError as e:
                self._set_context(context, e)
                logger.info(str(e))
                return self.response_type()
            except Exception as e:
                self._set_context(context, e)
                logger.exception(e)
                return self.response_type()

        return wrap_f
