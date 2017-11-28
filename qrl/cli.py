#!/usr/bin/env python3
import click
import grpc
from pyqrllib.pyqrllib import mnemonic2bin, hstr2bin

from qrl.core.Wallet import Wallet
from qrl.generated import qrl_pb2_grpc, qrl_pb2

from qrl.core.Transaction import Transaction


class CLIContext(object):
    def __init__(self, host, port_public, port_admin):
        self.host = host
        self.port_public = port_public
        self.port_admin = port_admin

        self.channel_public = grpc.insecure_channel(self.node_public_address)
        self.channel_admin = grpc.insecure_channel(self.node_admin_address)

    @property
    def node_public_address(self):
        return '{}:{}'.format(self.host, self.port_public)

    @property
    def node_admin_address(self):
        return '{}:{}'.format(self.host, self.port_admin)


@click.group()
@click.option('--host', default='127.0.0.1', help='host address')
@click.option('--port_pub', default=9009, help='port number (public api)')
@click.option('--port_adm', default=9008, help='port number (admin api)')
@click.pass_context
def qrl(ctx, host, port_pub, port_adm):
    """
    QRL Command Line Interface
    """
    ctx.obj = CLIContext(host, port_pub, port_adm)


def _get_local_addresses(ctx):
    stub = qrl_pb2_grpc.AdminAPIStub(ctx.obj.channel_admin)

    getAddressStateResp = stub.GetLocalAddresses(qrl_pb2.GetLocalAddressesReq(), timeout=5)

    return getAddressStateResp.addresses


def _get_address_balance(ctx, address):
    stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)

    getAddressStateReq = qrl_pb2.GetAddressStateReq(address=address)
    f = stub.GetAddressState.future(getAddressStateReq, timeout=5)
    getAddressStateResp = f.result(timeout=5)

    return getAddressStateResp.state.balance


def _get_wallet(ctx, address):
    stub = qrl_pb2_grpc.AdminAPIStub(ctx.obj.channel_admin)

    req = qrl_pb2.GetWalletReq()
    req.address = address

    getAddressStateResp = stub.GetWallet(req, timeout=5)

    return getAddressStateResp.wallet


def _print_wallet_list(ctx):
    addresses = _get_local_addresses(ctx)
    click.echo('{:<8}{:<75}{}'.format('Number', 'Address', 'Balance'))
    click.echo('-' * 95)
    for pos, addr in enumerate(addresses):
        balance = _get_address_balance(ctx, addr)
        # TODO standardize quanta/shor conversion
        click.echo('{:<8}{:<75}{:5.8f}'.format(pos, addr.decode(), balance / 1e8))


def select_wallet(walletObj):
    # FIXME: Get values from arguments, interactive only when necessary
    walletnum = click.prompt('Enter wallet number ', type=int)

    if 0 <= walletnum < len(walletObj.address_bundle):
        return walletObj.address_bundle[walletnum]

    click.echo('Invalid Wallet Number')
    return None


@qrl.command()
@click.pass_context
def wallets(ctx):
    """
    Lists available wallets
    """
    _print_wallet_list(ctx)


@qrl.command()
@click.option('--seed-type', type=click.Choice(['hexseed', 'mnemonic']), default='hexseed')
@click.pass_context
def recover(seed_type):
    """
    Recover Wallet using hexseed or mnemonic (32 words)
    """
    seed = click.prompt('Please enter your %s' % (seed_type,))
    seed = seed.lower().strip()

    if seed_type == 'mnemonic':
        words = seed.split()
        if len(words) != 32:
            print('You have entered %s words' % (len(words),))
            print('Mnemonic seed must contain only 32 words')
            return
        bin_seed = mnemonic2bin(seed)
    else:
        if len(seed) != 96:
            print('You have entered hexseed of %s characters' % (len(seed),))
            print('Hexseed must be of only 96 characters.')
            return
        bin_seed = hstr2bin(seed)

    walletObj = Wallet()
    addrBundle = walletObj.get_new_address(seed=bin_seed)
    print('Recovered Wallet Address : %s' % (addrBundle.address.decode(),))
    for addr in walletObj.address_bundle:
        if addrBundle.address == addr.address:
            print('Wallet Address is already in the wallet list')
            return

    if click.confirm('Do you want to save the recovered wallet?'):
        walletObj.address_bundle.append(addrBundle)
        click.echo('Saving...')
        walletObj.save_wallet()
        click.echo('Done')


@qrl.command()
@click.pass_context
def generate():
    """
    Generates new wallet address
    """
    walletObj = Wallet()
    click.echo('Generating...')
    addressBundle = walletObj.get_new_address()
    click.echo('Wallet Address     : %s' % (addressBundle.address.decode(),))
    click.echo('Hexseed            : %s' % (addressBundle.xmss.get_hexseed(),))
    click.echo('Mnemonic           : %s' % (addressBundle.xmss.get_mnemonic(),))

    if click.confirm('Do you want to save the generated wallet?'):
        walletObj.address_bundle.append(addressBundle)
        click.echo('Saving...')
        walletObj.save_wallet()
        click.echo('Done')


@qrl.command()
@click.option('--wallet-idx', default=0, prompt=True)
@click.pass_context
def mnemonic(ctx, wallet_idx):
    """
    Provides the mnemonic words of the address into wallet list.
    """
    addresses = _get_local_addresses(ctx)

    if 0 <= wallet_idx < len(addresses):
        wallet = _get_wallet(ctx, addresses[wallet_idx])

        click.echo('Wallet Address  : %s' % (wallet.address,))
        click.echo('Mnemonic        : %s' % (wallet.mnemonic,))
    else:
        click.echo('Wallet index not found', color='yellow')


@qrl.command()
@click.option('--from', default=0, prompt=True)
@click.option('--to', default=0, prompt=True)
@click.option('--amount', default=0, prompt=True)
@click.option('--fee', default=0, prompt=True)
@click.pass_context
def send(ctx):
    """
    Transfer coins
    """
    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)

    walletObj = Wallet()
    _print_wallet_list(walletObj)
    selected_wallet = select_wallet(walletObj)
    if not selected_wallet:
        return

    address_to = click.prompt('Enter Address To', type=str)
    amount = click.prompt('Enter Amount', type=float)
    fee = click.prompt('Fee', type=float)

    address_to = address_to.encode()
    int_amount = int(amount * 10 ** 8)
    int_fee = int(fee * 10 ** 8)

    try:
        transferCoinsReq = qrl_pb2.TransferCoinsReq(address_from=selected_wallet.address,
                                                    address_to=address_to,
                                                    amount=int_amount,
                                                    fee=int_fee,
                                                    xmss_pk=selected_wallet.xmss.pk(),
                                                    xmss_ots_index=selected_wallet.xmss.get_index())

        f = stub.TransferCoins.future(transferCoinsReq, timeout=5)
        transferCoinsResp = f.result(timeout=5)

        tx = Transaction.from_pbdata(transferCoinsResp.transaction_unsigned)
        tx.sign(selected_wallet.xmss)
        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)

        f = stub.PushTransaction.future(pushTransactionReq, timeout=5)
        pushTransactionResp = f.result(timeout=5)

        print('%s' % (pushTransactionResp.some_response,))
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.pass_context
def eph():
    # channel = get_channel()
    # stub = qrl_pb2_grpc.PublicAPIStub(channel)

    walletObj = Wallet()
    _print_wallet_list(walletObj)
    selected_wallet = select_wallet(walletObj)
    if not selected_wallet:
        return

    # address_to = click.prompt('Address To', type=str)
    # message = click.prompt('Message', type=str)


@qrl.command()
@click.pass_context
def lattice():
    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)

    walletObj = Wallet()
    _print_wallet_list(walletObj)
    selected_wallet = select_wallet(walletObj)
    if not selected_wallet:
        return

    lattice_public_key = click.prompt('Enter Lattice Public Key', type=str)

    lattice_public_key = lattice_public_key.encode()

    try:
        latticePublicKeyTxnReq = qrl_pb2.LatticePublicKeyTxnReq(address_from=selected_wallet.address,
                                                                kyber_pk=lattice_public_key,
                                                                tesla_pk=lattice_public_key,
                                                                xmss_pk=selected_wallet.xmss.pk(),
                                                                xmss_ots_index=selected_wallet.xmss.get_index())

        f = stub.GetLatticePublicKeyTxn.future(latticePublicKeyTxnReq, timeout=5)
        latticePublicKeyResp = f.result(timeout=5)

        tx = Transaction.from_pbdata(latticePublicKeyResp.transaction_unsigned)
        tx.sign(selected_wallet.xmss)
        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)

        f = stub.PushTransaction.future(pushTransactionReq, timeout=5)
        pushTransactionResp = f.result(timeout=5)

        print('%s' % (pushTransactionResp.some_response,))
    except Exception as e:
        print("Error {}".format(str(e)))


def main():
    qrl()


if __name__ == '__main__':
    main()
