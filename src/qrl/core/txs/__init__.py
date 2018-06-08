from importlib import import_module

TYPENAME_MAP = {
    'transfer': 'TransferTransaction',
    'coinbase': 'CoinBase',
    'latticePK': 'LatticePublicKey',
    'message': 'MessageTransaction',
    'token': 'TokenTransaction',
    'transfer_token': 'TransferTokenTransaction',
    'slave': 'SlaveTransaction'
}


def build_tx(pb_tx_type, *args, **kwargs):
    try:
        tx_class_name = TYPENAME_MAP[pb_tx_type]
        tx_module = import_module('.' + tx_class_name, package='qrl.core.txs')
        tx_class = getattr(tx_module, tx_class_name)
        return tx_class(*args, **kwargs)

    except(AttributeError, ModuleNotFoundError) as e:  # noqa
        raise ImportError("{} is not defined as a transaction type".format(pb_tx_type))
