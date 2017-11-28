#!/usr/bin/env python3
import click
import grpc

from qrl.core import config
from qrl.core.Wallet import Wallet
from qrl.generated import qrl_pb2_grpc, qrl_pb2

from qrl.core.Transaction import Transaction


class CLIContext(object):
    def __init__(self, remote, host, port_public, port_admin, wallet_dir):
        self.remote = remote
        self.host = host
        self.port_public = port_public
        self.port_admin = port_admin
        self.wallet_dir = wallet_dir

        self.channel_public = grpc.insecure_channel(self.node_public_address)
        self.channel_admin = grpc.insecure_channel(self.node_admin_address)

    @property
    def node_public_address(self):
        return '{}:{}'.format(self.host, self.port_public)

    @property
    def node_admin_address(self):
        return '{}:{}'.format(self.host, self.port_admin)


@click.group()
@click.option('--remote', '-r', default=False, is_flag=True, help='connect to remote node')
@click.option('--host', default='127.0.0.1', help='remote host address')
@click.option('--port_pub', default=9009, help='remote port number (public api)')
@click.option('--port_adm', default=9008, help='remote port number (admin api)')
@click.option('--wallet_dir', default='.', help='local wallet dir')
@click.pass_context
def qrl(ctx, remote, host, port_pub, port_adm, wallet_dir):
    """
    QRL Command Line Interface
    """
    ctx.obj = CLIContext(remote=remote,
                         host=host,
                         port_public=port_pub,
                         port_admin=port_adm,
                         wallet_dir=wallet_dir)


def _admin_get_local_addresses(ctx):
    try:
        stub = qrl_pb2_grpc.AdminAPIStub(ctx.obj.channel_admin)
        getAddressStateResp = stub.GetLocalAddresses(qrl_pb2.GetLocalAddressesReq(), timeout=5)
        return getAddressStateResp.addresses
    except:
        click.echo('Error connecting to node', color='red')
        return []


def _admin_get_wallet(ctx, address):
    stub = qrl_pb2_grpc.AdminAPIStub(ctx.obj.channel_admin)

    req = qrl_pb2.GetWalletReq()
    req.address = address

    getAddressStateResp = stub.GetWallet(req, timeout=5)

    return getAddressStateResp.wallet


def _print_addresses(ctx, addresses, source_description):
    if len(addresses) == 0:
        click.echo('No wallet found at {}'.format(source_description))
        return

    click.echo('Wallet at          : {}'.format(source_description))
    click.echo('{:<8}{:<75}{}'.format('Number', 'Address', 'Balance'))
    click.echo('-' * 95)

    for pos, addr in enumerate(addresses):
        try:
            balance = _public_get_address_balance(ctx, addr)
            # TODO standardize quanta/shor conversion
            balance /= 1e8
            click.echo('{:<8}{:<75}{:5.8f}'.format(pos, addr.decode(), balance))
        except Exception:
            click.echo('{:<8}{:<75}?'.format(pos, addr.decode()))


def _public_get_address_balance(ctx, address):
    stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)
    getAddressStateReq = qrl_pb2.GetAddressStateReq(address=address)
    getAddressStateResp = stub.GetAddressState(getAddressStateReq, timeout=1)
    return getAddressStateResp.state.balance


def select_wallet(walletObj):
    # FIXME: Get values from arguments, interactive only when necessary
    walletnum = click.prompt('Enter wallet number ', type=int)

    if 0 <= walletnum < len(walletObj.address_bundle):
        return walletObj.address_bundle[walletnum]

    click.echo('Invalid Wallet Number')
    return None


########################
########################
########################
########################

@qrl.command()
@click.pass_context
def wallet_ls(ctx):
    """
    Lists available wallets
    """
    if ctx.obj.remote:
        addresses = _admin_get_local_addresses(ctx)
        _print_addresses(ctx, addresses, ctx.obj.node_public_address)
    else:
        config.user.wallet_path = ctx.obj.wallet_dir
        wallet = Wallet(valid_or_create=False)
        addresses = [a.address for a in wallet.address_bundle]
        _print_addresses(ctx, addresses, config.user.wallet_path)


@qrl.command()
@click.pass_context
def wallet_gen(ctx):
    """
    Adds an address or generates a new wallet (working directory)
    """
    if ctx.obj.remote:
        click.echo('This command is unsupported for remote wallets')
        return

    config.user.wallet_path = ctx.obj.wallet_dir
    wallet = Wallet()
    wallet.append(wallet.get_new_address())

    addresses = [a.address for a in wallet.address_bundle]
    _print_addresses(ctx, addresses, config.user.wallet_path)


# @qrl.command()
# @click.option('--seed-type', type=click.Choice(['hexseed', 'mnemonic']), default='hexseed')
# @click.pass_context
# def recover(seed_type):
#     """
#     Recover Wallet using hexseed or mnemonic (32 words)
#     """
#     seed = click.prompt('Please enter your %s' % (seed_type,))
#     seed = seed.lower().strip()
#
#     if seed_type == 'mnemonic':
#         words = seed.split()
#         if len(words) != 32:
#             print('You have entered %s words' % (len(words),))
#             print('Mnemonic seed must contain only 32 words')
#             return
#         bin_seed = mnemonic2bin(seed)
#     else:
#         if len(seed) != 96:
#             print('You have entered hexseed of %s characters' % (len(seed),))
#             print('Hexseed must be of only 96 characters.')
#             return
#         bin_seed = hstr2bin(seed)
#
#     walletObj = Wallet()
#     addrBundle = walletObj.get_new_address(seed=bin_seed)
#     print('Recovered Wallet Address : %s' % (addrBundle.address.decode(),))
#     for addr in walletObj.address_bundle:
#         if addrBundle.address == addr.address:
#             print('Wallet Address is already in the wallet list')
#             return
#
#     if click.confirm('Do you want to save the recovered wallet?'):
#         walletObj.address_bundle.append(addrBundle)
#         click.echo('Saving...')
#         walletObj.save_wallet()
#         click.echo('Done')


@qrl.command()
@click.option('--wallet-idx', default=0, prompt=True)
@click.pass_context
def wallet_secret(ctx, wallet_idx):
    """
    Provides the mnemonic/hexseed of the given address index
    """
    if ctx.obj.remote:
        addresses = _admin_get_local_addresses(ctx)

        if 0 <= wallet_idx < len(addresses):
            wallet = _admin_get_wallet(ctx, addresses[wallet_idx])

            click.echo('Wallet Address  : %s' % (wallet.address,))
            click.echo('Mnemonic        : %s' % (wallet.mnemonic,))
        else:
            click.echo('Wallet index not found', color='yellow')

    else:
        config.user.wallet_path = ctx.obj.wallet_dir

        wallet = Wallet(valid_or_create=False)

        if 0 <= wallet_idx < len(wallet.address_bundle):
            addr_bundle = wallet.address_bundle[wallet_idx]
            click.echo('Wallet Address  : %s' % (addr_bundle.address.decode()))
            click.echo('Mnemonic        : %s' % (addr_bundle.xmss.get_mnemonic()))
        else:
            click.echo('Wallet index not found', color='yellow')


@qrl.command()
@click.option('--src', default='', prompt=True)
@click.option('--dst', default='', prompt=True)
@click.option('--amount', default=0, prompt=True)
@click.option('--fee', default=0, prompt=True)
@click.pass_context
def tx_prepare(ctx, src, dst, amount, fee):
    """
    Request a tx blob from src to dst (unsigned)
    """
    pass


@qrl.command()
@click.option('--src', default='', prompt=True)
@click.option('--dst', default='', prompt=True)
@click.option('--amount', default=0, prompt=True)
@click.option('--fee', default=0, prompt=True)
@click.pass_context
def tx_sign(ctx, src, dst, amount, fee):
    """
    Sign a tx blob
    """


@qrl.command()
@click.option('--src', default='', prompt=True)
@click.option('--dst', default='', prompt=True)
@click.option('--amount', default=0, prompt=True)
@click.option('--fee', default=0, prompt=True)
@click.pass_context
def tx_transfer(ctx, src, dst, amount, fee):
    """
    Transfer coins from src to dst
    """
    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)

    address_src = src.encode()
    address_dst = dst.encode()

    # FIXME: This could be problematic. Check
    amount_shor = int(amount * 10 ** 8)
    fee_shor = int(fee * 10 ** 8)

    try:
        transferCoinsReq = qrl_pb2.TransferCoinsReq(address_from=address_src,
                                                    address_to=address_dst,
                                                    amount=amount_shor,
                                                    fee=fee_shor,
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


# @qrl.command()
# @click.pass_context
# def eph(ctx):
#     stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)
#
#     walletObj = Wallet()
#     _admin_print_wallet_list(walletObj)
#     selected_wallet = select_wallet(walletObj)
#     if not selected_wallet:
#         return
#
#     # address_to = click.prompt('Address To', type=str)
#     # message = click.prompt('Message', type=str)
#
#
# @qrl.command()
# @click.pass_context
# def lattice(ctx):
#     stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)
#
#     walletObj = Wallet()
#     _admin_print_wallet_list(walletObj)
#     selected_wallet = select_wallet(walletObj)
#     if not selected_wallet:
#         return
#
#     lattice_public_key = click.prompt('Enter Lattice Public Key', type=str)
#
#     lattice_public_key = lattice_public_key.encode()
#
#     try:
#         latticePublicKeyTxnReq = qrl_pb2.LatticePublicKeyTxnReq(address_from=selected_wallet.address,
#                                                                 kyber_pk=lattice_public_key,
#                                                                 tesla_pk=lattice_public_key,
#                                                                 xmss_pk=selected_wallet.xmss.pk(),
#                                                                 xmss_ots_index=selected_wallet.xmss.get_index())
#
#         f = stub.GetLatticePublicKeyTxn.future(latticePublicKeyTxnReq, timeout=5)
#         latticePublicKeyResp = f.result(timeout=5)
#
#         tx = Transaction.from_pbdata(latticePublicKeyResp.transaction_unsigned)
#         tx.sign(selected_wallet.xmss)
#         pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
#
#         f = stub.PushTransaction.future(pushTransactionReq, timeout=5)
#         pushTransactionResp = f.result(timeout=5)
#
#         print('%s' % (pushTransactionResp.some_response,))
#     except Exception as e:
#         print("Error {}".format(str(e)))


def main():
    qrl()


if __name__ == '__main__':
    main()
