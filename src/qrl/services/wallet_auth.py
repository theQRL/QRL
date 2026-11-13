import hmac

import grpc


TOKEN_HEADER = 'x-qrl-wallet-token'


class WalletAuthInterceptor(grpc.ServerInterceptor):
    def __init__(self, token):
        if not token:
            raise ValueError('Wallet API token is required')
        self._token = token

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        tokens = [value for key, value in handler_call_details.invocation_metadata
                  if key == TOKEN_HEADER]
        if len(tokens) == 1 and isinstance(tokens[0], str) and hmac.compare_digest(tokens[0], self._token):
            return handler

        def reject(request, context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, 'Wallet API token required')

        return grpc.unary_unary_rpc_method_handler(
            reject,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer)
