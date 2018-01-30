#!/usr/bin/env python3
import os

import click
import grpc
import simplejson as json
from pyqrllib.pyqrllib import mnemonic2bin, hstr2bin, bin2hstr

from qrl.core import config
from qrl.crypto.xmss import XMSS
from qrl.core.Transaction import Transaction, TokenTransaction, TransferTokenTransaction
from qrl.core.Wallet import Wallet
from qrl.generated import qrl_pb2_grpc, qrl_pb2

ENV_QRL_WALLET_DIR = 'ENV_QRL_WALLET_DIR'


class CLIContext(object):

    def __init__(self, remote, host, port_public, port_admin, wallet_dir):
        self.remote = remote
        self.host = host
        self.port_public = port_public
        self.port_admin = port_admin

        self.wallet_dir = os.path.abspath(wallet_dir)

        self.channel_public = grpc.insecure_channel(self.node_public_address)
        self.channel_admin = grpc.insecure_channel(self.node_admin_address)

    @property
    def node_public_address(self):
        return '{}:{}'.format(self.host, self.port_public)

    @property
    def node_admin_address(self):
        return '{}:{}'.format(self.host, self.port_admin)


def _admin_get_local_addresses(ctx):
    try:
        stub = qrl_pb2_grpc.AdminAPIStub(ctx.obj.channel_admin)
        getAddressStateResp = stub.GetLocalAddresses(qrl_pb2.GetLocalAddressesReq(), timeout=5)
        return getAddressStateResp.addresses
    except Exception as e:
        click.echo('Error connecting to node', color='red')
        return []


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
            balance /= 1e9
            click.echo('{:<8}{:<75}{:5.8f}'.format(pos, addr.decode(), balance))
        except Exception as e:
            click.echo('{:<8}{:<75}?'.format(pos, addr.decode()))


def _public_get_address_balance(ctx, address):
    stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)
    getAddressStateReq = qrl_pb2.GetAddressStateReq(address=address)
    getAddressStateResp = stub.GetAddressState(getAddressStateReq, timeout=1)
    return getAddressStateResp.state.balance


def _select_wallet(ctx, src):
    try:
        config.user.wallet_dir = ctx.obj.wallet_dir
        wallet = Wallet(valid_or_create=False)
        addresses = [a.address for a in wallet.address_bundle]
        if not addresses:
            click.echo('This command requires a local wallet')
            return

        if src.isdigit():
            try:
                # FIXME: This should only return pk and index
                ab = wallet.address_bundle[int(src)]
                return ab.address, ab.xmss
            except IndexError:
                click.echo('Wallet index not found', color='yellow')
                quit(1)

        elif src.startswith('Q'):
            for i, addr in enumerate(wallet.addresses):
                if src.encode() == addr:
                    return wallet.address_bundle[i].address, wallet.address_bundle[i].xmss
            click.echo('Source address not found in your wallet', color='yellow')
            quit(1)

        return src.encode(), None
    except Exception as e:
        click.echo("Error selecting wallet")
        quit(1)


########################
########################
########################
########################

@click.group()
@click.option('--remote', '-r', default=False, is_flag=True, help='connect to remote node')
@click.option('--host', default='127.0.0.1', help='remote host address             [127.0.0.1]')
@click.option('--port_pub', default=9009, help='remote port number (public api) [9009]')
@click.option('--port_adm', default=9008, help='remote port number (admin api)  [9009]* will change')
@click.option('--wallet_dir', default='.', help='local wallet dir', envvar=ENV_QRL_WALLET_DIR)
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
        config.user.wallet_dir = ctx.obj.wallet_dir
        wallet = Wallet(valid_or_create=False)
        addresses = [a.address for a in wallet.address_bundle]
        _print_addresses(ctx, addresses, config.user.wallet_dir)


@qrl.command()
@click.pass_context
def wallet_gen(ctx):
    """
    Generates a new wallet with one address
    """
    if ctx.obj.remote:
        click.echo('This command is unsupported for remote wallets')
        return

    config.user.wallet_dir = ctx.obj.wallet_dir
    wallet = Wallet()

    addresses = [a.address for a in wallet.address_bundle]
    _print_addresses(ctx, addresses, config.user.wallet_dir)


@qrl.command()
@click.pass_context
def wallet_add(ctx):
    """
    Adds an address or generates a new wallet (working directory)
    """
    if ctx.obj.remote:
        click.echo('This command is unsupported for remote wallets')
        return

    config.user.wallet_dir = ctx.obj.wallet_dir
    wallet = Wallet()
    wallet.append(wallet.get_new_address())

    addresses = [a.address for a in wallet.address_bundle]
    _print_addresses(ctx, addresses, config.user.wallet_dir)


@qrl.command()
@click.option('--seed-type', type=click.Choice(['hexseed', 'mnemonic']), default='hexseed')
@click.pass_context
def wallet_recover(ctx, seed_type):
    """
    Recovers a wallet from a hexseed or mnemonic (32 words)
    """
    if ctx.obj.remote:
        click.echo('This command is unsupported for remote wallets')
        return

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

    config.user.wallet_dir = ctx.obj.wallet_dir
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
@click.option('--wallet-idx', default=0, prompt=True)
@click.pass_context
def wallet_secret(ctx, wallet_idx):
    """
    Provides the mnemonic/hexseed of the given address index
    """
    if ctx.obj.remote:
        click.echo('This command is unsupported for remote wallets')
        return

    config.user.wallet_dir = ctx.obj.wallet_dir

    wallet = Wallet(valid_or_create=False)

    if 0 <= wallet_idx < len(wallet.address_bundle):
        addr_bundle = wallet.address_bundle[wallet_idx]
        click.echo('Wallet Address  : %s' % (addr_bundle.address.decode()))
        click.echo('Mnemonic        : %s' % (addr_bundle.xmss.get_mnemonic()))
    else:
        click.echo('Wallet index not found', color='yellow')


@qrl.command()
@click.option('--src', default='', prompt=True, help='source address or index')
@click.option('--dst', default='', prompt=True, help='destination address')
@click.option('--amount', default=0.0, type=float, prompt=True, help='amount to transfer (Quanta)')
@click.option('--fee', default=0.0, type=float, prompt=True, help='fee (Quanta)')
@click.option('--pk', default=0, prompt=False, help='public key (when local wallet is missing)')
@click.option('--otsidx', default=0, prompt=False, help='OTS index (when local wallet is missing)')
@click.pass_context
def tx_prepare(ctx, src, dst, amount, fee, pk, otsidx):
    """
    Request a tx blob (unsigned) to transfer from src to dst (uses local wallet)
    """
    try:
        address_src, src_xmss = _select_wallet(ctx, src)
        if src_xmss:
            address_src_pk = src_xmss.pk()
            address_src_otsidx = src_xmss.get_index()
        else:
            address_src_pk = pk.encode()
            address_src_otsidx = int(otsidx)

        address_dst = dst.encode()
        amount_shor = int(amount * 1.e9)
        fee_shor = int(fee * 1.e9)
    except Exception as e:
        click.echo("Error validating arguments")
        quit(1)

    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    # FIXME: This could be problematic. Check
    transferCoinsReq = qrl_pb2.TransferCoinsReq(address_from=address_src,
                                                address_to=address_dst,
                                                amount=amount_shor,
                                                fee=fee_shor,
                                                xmss_pk=address_src_pk,
                                                xmss_ots_index=address_src_otsidx)

    try:
        transferCoinsResp = stub.TransferCoins(transferCoinsReq, timeout=5)
    except grpc.RpcError as e:
        click.echo(e.details())
        quit(1)
    except Exception as e:
        click.echo("Unhandled error: {}".format(str(e)))
        quit(1)

    txblob = bin2hstr(transferCoinsResp.transaction_unsigned.SerializeToString())
    print(txblob)


@qrl.command()
@click.option('--src', default='', prompt=True, help='source address or index')
@click.option('--addr_from', default='', prompt="Addr from (Leave blank in case same as source)", help='Address from')
@click.option('--number_of_slaves', default=0, type=int, prompt=True, help='Number of slaves addresses')
@click.option('--access_type', default=0, type=int, prompt=True, help='0 - All Permission, 1 - Only Mining Permission')
@click.option('--fee', default=0.0, type=float, prompt=True, help='fee (Quanta)')
@click.option('--pk', default=0, prompt=False, help='public key (when local wallet is missing)')
@click.option('--otsidx', default=0, prompt=False, help='OTS index (when local wallet is missing)')
@click.pass_context
def slave_tx_generate(ctx, src, addr_from, number_of_slaves, access_type, fee, pk, otsidx):
    """
    Generates Slave Transaction for the wallet
    """
    try:
        address_src, src_xmss = _select_wallet(ctx, src)
        if len(addr_from.strip()) == 0:
            addr_from = address_src
        if src_xmss:
            address_src_pk = src_xmss.pk()
            address_src_otsidx = src_xmss.get_index()
        else:
            address_src_pk = pk.encode()
            address_src_otsidx = int(otsidx)

        fee_shor = int(fee * 1.e9)
    except Exception as e:
        click.echo("Error validating arguments")
        quit(1)

    slave_xmss = []
    slave_pks = []
    access_types = []
    slave_xmss_seed = []
    if number_of_slaves > 100:
        click.echo("Error: Max Limit for the number of slaves is 100")
        quit(1)

    for i in range(number_of_slaves):
        print("Generating Slave #"+str(i+1))
        xmss = XMSS(config.dev.xmss_tree_height)
        slave_xmss.append(xmss)
        slave_xmss_seed.append(xmss.get_seed())
        slave_pks.append(xmss.pk())
        access_types.append(access_type)
        print("Successfully Generated Slave %s/%s" % (str(i + 1), number_of_slaves))

    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    # FIXME: This could be problematic. Check
    slaveTxnReq = qrl_pb2.SlaveTxnReq(address_from=addr_from,
                                      slave_pks=slave_pks,
                                      access_types=access_types,
                                      fee=fee_shor,
                                      xmss_pk=address_src_pk,
                                      xmss_ots_index=address_src_otsidx)

    try:
        slaveTxnResp = stub.GetSlaveTxn(slaveTxnReq, timeout=5)
        tx = Transaction.from_pbdata(slaveTxnResp.transaction_unsigned)
        tx.sign(src_xmss)
        with open('slaves.json', 'w') as f:
            json.dump([src_xmss.get_address(), slave_xmss_seed, tx.to_json()], f)
        click.echo('Successfully created slaves.json')
        click.echo('Move slaves.json file from current directory to the mining node inside ~/.qrl/')
    except grpc.RpcError as e:
        click.echo(e.details())
        quit(1)
    except Exception as e:
        click.echo("Unhandled error: {}".format(str(e)))
        quit(1)


@qrl.command()
@click.option('--src', default='', prompt=True, help='signing address index')
@click.option('--txblob', default='', prompt=True, help='transaction blob (unsigned)')
@click.pass_context
def tx_sign(ctx, src, txblob):
    """
    Sign a tx blob
    """
    txbin = bytes(hstr2bin(txblob))
    pbdata = qrl_pb2.Transaction()
    pbdata.ParseFromString(txbin)
    tx = Transaction.from_pbdata(pbdata)

    address_src, address_xmss = _select_wallet(ctx, src)
    tx.sign(address_xmss)

    txblob = bin2hstr(tx.pbdata.SerializeToString())
    print(txblob)


@qrl.command()
@click.option('--txblob', default='', prompt=True, help='transaction blob (unsigned)')
@click.pass_context
def tx_inspect(ctx, txblob):
    """
    Inspected a transaction blob
    """
    tx = None
    try:
        txbin = bytes(hstr2bin(txblob))
        pbdata = qrl_pb2.Transaction()
        pbdata.ParseFromString(txbin)
        tx = Transaction.from_pbdata(pbdata)
    except Exception as e:
        click.echo("tx blob is not valid")
        quit(1)

    tmp_json = tx.to_json()
    # FIXME: binary fields are represented in base64. Improve output
    print(tmp_json)


@qrl.command()
@click.option('--txblob', default='', prompt=True, help='transaction blob (unsigned)')
@click.pass_context
def tx_push(ctx, txblob):
    tx = None
    try:
        txbin = bytes(hstr2bin(txblob))
        pbdata = qrl_pb2.Transaction()
        pbdata.ParseFromString(txbin)
        tx = Transaction.from_pbdata(pbdata)
    except Exception as e:
        click.echo("tx blob is not valid")
        quit(1)

    tmp_json = tx.to_json()
    # FIXME: binary fields are represented in base64. Improve output
    print(tmp_json)
    if (len(tx.signature) == 0):
        click.echo('Signature missing')
        quit(1)

    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
    pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)
    print(pushTransactionResp.some_response)


@qrl.command()
@click.option('--src', default='', prompt=True, help='source QRL address')
@click.option('--dst', default='', prompt=True, help='destination QRL address')
@click.option('--amount', default=0.0, prompt=True, help='amount to transfer in Quanta')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.pass_context
def tx_transfer(ctx, src, dst, amount, fee):
    """
    Transfer coins from src to dst
    """
    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    try:
        address_src, src_xmss = _select_wallet(ctx, src)
        if not src_xmss:
            click.echo("A local wallet is required to sign the transaction")
            quit(1)

        address_src_pk = src_xmss.pk()
        address_src_otsidx = src_xmss.get_index()
        address_dst = dst.encode()
        # FIXME: This could be problematic. Check
        amount_shor = int(amount * 1.e9)
        fee_shor = int(fee * 1.e9)
    except Exception as e:
        click.echo("Error validating arguments")
        quit(1)

    try:
        channel = grpc.insecure_channel(ctx.obj.node_public_address)
        stub = qrl_pb2_grpc.PublicAPIStub(channel)
        transferCoinsReq = qrl_pb2.TransferCoinsReq(address_from=address_src,
                                                    address_to=address_dst,
                                                    amount=amount_shor,
                                                    fee=fee_shor,
                                                    xmss_pk=address_src_pk,
                                                    xmss_ots_index=address_src_otsidx)

        transferCoinsResp = stub.TransferCoins(transferCoinsReq, timeout=5)

        tx = Transaction.from_pbdata(transferCoinsResp.transaction_unsigned)
        tx.sign(src_xmss)

        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)

        print(pushTransactionResp.some_response)
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--src', default='', prompt=True, help='source QRL address')
@click.option('--symbol', default='', prompt=True, help='Symbol Name')
@click.option('--name', default='', prompt=True, help='Token Name')
@click.option('--owner', default='', prompt=True, help='Owner QRL address')
@click.option('--decimals', default=0, prompt=True, help='decimals')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.option('--ots_key_index', default=0, prompt=True, help='OTS key Index')
@click.pass_context
def tx_token(ctx, src, symbol, name, owner, decimals, fee, ots_key_index):
    """
    Create Token Transaction, that results into the formation of new token if accepted.
    """

    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    initial_balances = []

    while True:
        address = click.prompt('Address ', default='')
        if address == '':
            break
        amount = int(click.prompt('Amount ')) * (10**int(decimals))
        initial_balances.append(qrl_pb2.AddressAmount(address=address.encode(), amount=amount))

    try:
        address_src, src_xmss = _select_wallet(ctx, src)
        if not src_xmss:
            click.echo("A local wallet is required to sign the transaction")
            quit(1)

        address_src_pk = src_xmss.pk()
        src_xmss.set_index(int(ots_key_index))
        address_src_otsidx = src_xmss.get_index()
        address_owner = owner.encode()
        # FIXME: This could be problematic. Check
        fee_shor = int(fee * 1.e9)
    except KeyboardInterrupt as e:
        click.echo("Error validating arguments")
        quit(1)

    try:
        channel = grpc.insecure_channel(ctx.obj.node_public_address)
        stub = qrl_pb2_grpc.PublicAPIStub(channel)

        tx = TokenTransaction.create(addr_from=address_src,
                                     symbol=symbol.encode(),
                                     name=name.encode(),
                                     owner=address_owner,
                                     decimals=decimals,
                                     initial_balances=initial_balances,
                                     fee=fee_shor,
                                     xmss_pk=address_src_pk,
                                     xmss_ots_index=address_src_otsidx)

        tx.sign(src_xmss)

        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)

        print(pushTransactionResp.some_response)
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--src', default='', prompt=True, help='source QRL address')
@click.option('--token_txhash', default='', prompt=True, help='Token Txhash')
@click.option('--dst', default='', prompt=True, help='Destination QRL address')
@click.option('--amount', default=0.0, prompt=True, help='amount')
@click.option('--decimals', default=0, prompt=True, help='decimals')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.option('--ots_key_index', default=0, prompt=True, help='OTS key Index')
@click.pass_context
def tx_transfertoken(ctx, src, token_txhash, dst, amount, decimals, fee, ots_key_index):
    """
    Create Token Transaction, that results into the formation of new token if accepted.
    """

    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    try:
        address_src, src_xmss = _select_wallet(ctx, src)
        if not src_xmss:
            click.echo("A local wallet is required to sign the transaction")
            quit(1)

        address_src_pk = src_xmss.pk()
        src_xmss.set_index(int(ots_key_index))
        address_src_otsidx = src_xmss.get_index()
        address_dst = dst.encode()
        bin_token_txhash = bytes(hstr2bin(token_txhash))
        # FIXME: This could be problematic. Check
        amount = int(amount * (10**int(decimals)))
        fee_shor = int(fee * 1.e9)
    except KeyboardInterrupt as e:
        click.echo("Error validating arguments")
        quit(1)

    try:
        channel = grpc.insecure_channel(ctx.obj.node_public_address)
        stub = qrl_pb2_grpc.PublicAPIStub(channel)

        tx = TransferTokenTransaction.create(addr_from=address_src,
                                             token_txhash=bin_token_txhash,
                                             addr_to=address_dst,
                                             amount=amount,
                                             fee=fee_shor,
                                             xmss_pk=address_src_pk,
                                             xmss_ots_index=address_src_otsidx)
        tx.sign(src_xmss)

        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)

        print(pushTransactionResp.some_response)
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--owner', default='', prompt=True, help='source QRL address')
@click.pass_context
def token_list(ctx, owner):
    """
    Create Token Transaction, that results into the formation of new token if accepted.
    """

    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    try:

        channel = grpc.insecure_channel(ctx.obj.node_public_address)
        stub = qrl_pb2_grpc.PublicAPIStub(channel)
        addressStateReq = qrl_pb2.GetAddressStateReq(address=owner.encode())
        addressStateResp = stub.GetAddressState(addressStateReq, timeout=5)

        for token_hash in addressStateResp.state.tokens:
            click.echo('Hash: %s' % (token_hash, ))
            click.echo('Balance: %s' % (addressStateResp.state.tokens[token_hash], ))
    except Exception as e:
        print("Error {}".format(str(e)))


# FIXME: Enable back
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


# FIXME: Enable back
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
