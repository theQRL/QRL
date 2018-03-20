#!/usr/bin/env python3
import os
from collections import namedtuple
from decimal import Decimal
from typing import List

import click
import grpc
import simplejson as json
from google.protobuf.json_format import MessageToJson
from pyqrllib.pyqrllib import mnemonic2bin, hstr2bin, bin2hstr

from qrl.core import config
from qrl.core.EphemeralMessage import EncryptedEphemeralMessage
from qrl.core.Transaction import Transaction, TokenTransaction, TransferTokenTransaction, LatticePublicKey
from qrl.core.Wallet import Wallet
from qrl.crypto.xmss import XMSS
from qrl.generated import qrl_pb2_grpc, qrl_pb2

ENV_QRL_WALLET_DIR = 'ENV_QRL_WALLET_DIR'

OutputMessage = namedtuple('OutputMessage',
                           'error address_items balance_items')

BalanceItem = namedtuple('BalanceItem',
                         'address balance')


class CLIContext(object):

    def __init__(self, remote, host, port_public, port_admin, wallet_dir, json):
        self.remote = remote
        self.host = host
        self.port_public = port_public
        self.port_admin = port_admin

        self.wallet_dir = os.path.abspath(wallet_dir)
        self.json = json

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


def _print_error(ctx, error_descr, wallets=None):
    if ctx.obj.json:
        if wallets is None:
            wallets = []
        msg = {'error': error_descr, 'wallets': wallets}
        click.echo(json.dumps(msg))
    else:
        print("ERROR: {}".format(error_descr))


def _serialize_output(ctx, addresses: List[OutputMessage], source_description) -> str:
    if len(addresses) == 0:
        msg = json.dumps({'error': 'No wallet found at {}'.format(source_description), 'wallets': []})
        return msg

    msg = {'error': None, 'wallets': []}

    for pos, item in enumerate(addresses):
        try:
            balance = Decimal(_public_get_address_balance(ctx, item.address)) / config.dev.shor_per_quanta
            msg['wallets'].append({'number': pos, 'address': item.address, 'balance': balance})
        except Exception as e:
                msg['error'] = str(e)
                msg['wallets'].append({'number': pos, 'address': item.address, 'balance': '?'})
    return msg


def _print_addresses(ctx, addresses: List[OutputMessage], source_description):
    output = _serialize_output(ctx, addresses, source_description)
    if ctx.obj.json:
        click.echo(output)
    else:
        if output['error'] and output['wallets'] == []:
            click.echo(output['error'])
        else:
            click.echo("Wallet at          : {}".format(source_description))
            click.echo("{:<8}{:<83}{}".format('Number', 'Address', 'Balance'))
            click.echo('-' * 99)
            for wallet in output['wallets']:
                if isinstance(wallet['balance'], str):
                    click.echo("{:<8}{:<83} {}".format(wallet['number'], wallet['address'], wallet['balance']))
                else:
                    click.echo("{:<8}{:<83}{:5.8f}".format(wallet['number'], wallet['address'], wallet['balance']))


def _public_get_address_balance(ctx, address):
    address = address[1:]
    stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)
    getAddressStateReq = qrl_pb2.GetAddressStateReq(address=bytes(hstr2bin(address)))
    getAddressStateResp = stub.GetAddressState(getAddressStateReq, timeout=1)
    return getAddressStateResp.state.balance


def _select_wallet(ctx, src):
    try:
        config.user.wallet_dir = ctx.obj.wallet_dir
        wallet = Wallet()
        if not wallet.addresses:
            click.echo('This command requires a local wallet')
            return

        if src.isdigit():
            src = int(src)
            try:
                # FIXME: This should only return pk and index
                xmss = wallet.get_xmss_by_index(src)
                return wallet.addresses[src], xmss
            except IndexError:
                click.echo('Wallet index not found', color='yellow')
                quit(1)

        elif src.startswith('Q'):
            for i, addr_item in enumerate(wallet.address_items):
                if src == addr_item.address:
                    xmss = wallet.get_xmss_by_address(wallet.addresses[i])
                    return wallet.addresses[i], xmss
            click.echo('Source address not found in your wallet', color='yellow')
            quit(1)

        return bytes(hstr2bin(src)), None
    except Exception as e:
        click.echo("Error selecting wallet")
        quit(1)


########################
########################
########################
########################

@click.version_option(version=config.dev.version, prog_name='QRL Command Line Interface')
@click.group()
@click.option('--remote', '-r', default=False, is_flag=True, help='connect to remote node')
@click.option('--host', default='127.0.0.1', help='remote host address             [127.0.0.1]')
@click.option('--port_pub', default=9009, help='remote port number (public api) [9009]')
@click.option('--port_adm', default=9008, help='remote port number (admin api)  [9009]* will change')
@click.option('--wallet_dir', default='.', help='local wallet dir', envvar=ENV_QRL_WALLET_DIR)
@click.option('--json', default=False, is_flag=True, help='output in json')
@click.pass_context
def qrl(ctx, remote, host, port_pub, port_adm, wallet_dir, json):
    """
    QRL Command Line Interface
    """
    ctx.obj = CLIContext(remote=remote,
                         host=host,
                         port_public=port_pub,
                         port_admin=port_adm,
                         wallet_dir=wallet_dir,
                         json=json)


@qrl.command()
@click.pass_context
def wallet_ls(ctx):
    """
    Lists available wallets
    """
    config.user.wallet_dir = ctx.obj.wallet_dir
    wallet = Wallet()
    _print_addresses(ctx, wallet.address_items, config.user.wallet_dir)


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
    # FIXME: If the wallet is there, it should fail
    wallet = Wallet()
    if len(wallet.address_items) == 0:
        wallet.add_new_address(config.dev.xmss_tree_height)
        _print_addresses(ctx, wallet.address_items, config.user.wallet_dir)
    else:
        # FIXME: !!!!!
        click.echo("Wallet already exists")


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
    wallet.add_new_address(config.dev.xmss_tree_height)
    _print_addresses(ctx, wallet.address_items, config.user.wallet_dir)


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
        if len(words) != 34:
            print('You have entered %s words' % (len(words),))
            print('Mnemonic seed must contain only 34 words')
            return
        bin_seed = mnemonic2bin(seed)
    else:
        if len(seed) != 102:
            print('You have entered hexseed of %s characters' % (len(seed),))
            print('Hexseed must be of only 102 characters.')
            return
        bin_seed = hstr2bin(seed)

    config.user.wallet_dir = ctx.obj.wallet_dir
    walletObj = Wallet()
    recovered_xmss = XMSS.from_extended_seed(bin_seed)
    print('Recovered Wallet Address : %s' % (recovered_xmss.address,))
    for addr in walletObj.address_items:
        if recovered_xmss.address == addr.address:
            print('Wallet Address is already in the wallet list')
            return

    if click.confirm('Do you want to save the recovered wallet?'):
        click.echo('Saving...')
        walletObj.append_xmss(recovered_xmss)
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

    wallet = Wallet()

    if 0 <= wallet_idx < len(wallet.address_items):
        address_item = wallet.address_items[wallet_idx]
        click.echo('Wallet Address  : %s' % (address_item.address))
        click.echo('Mnemonic        : %s' % (address_item.mnemonic))
        click.echo('Hexseed         : %s' % (address_item.hexseed))
    else:
        click.echo('Wallet index not found', color='yellow')


@qrl.command()
@click.option('--src', default='', prompt=True, help='source address or index')
@click.option('--master', default='', prompt=True, help='master QRL address')
@click.option('--dst', type=str, prompt=True, help='List of destination addresses')
@click.option('--amounts', type=str, prompt=True, help='List of amounts to transfer (Quanta)')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.option('--pk', default=0, prompt=False, help='public key (when local wallet is missing)')
@click.pass_context
def tx_prepare(ctx, src, master, dst, amounts, fee, pk):
    """
    Request a tx blob (unsigned) to transfer from src to dst (uses local wallet)
    """
    try:
        _, src_xmss = _select_wallet(ctx, src)
        if src_xmss:
            address_src_pk = src_xmss.pk
        else:
            address_src_pk = pk.encode()

        addresses_dst = []
        for addr in dst.split(' '):
            addresses_dst.append(bytes(hstr2bin(addr[1:])))

        shor_amounts = []
        for amount in amounts.split(' '):
            shor_amounts.append(int(float(amount) * 1.e9))
        fee_shor = int(fee * 1.e9)
    except Exception as e:
        click.echo("Error validating arguments")
        quit(1)

    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    # FIXME: This could be problematic. Check
    transferCoinsReq = qrl_pb2.TransferCoinsReq(addresses_to=addresses_dst,
                                                amounts=shor_amounts,
                                                fee=fee_shor,
                                                xmss_pk=address_src_pk,
                                                master_addr=master.encode())

    try:
        transferCoinsResp = stub.TransferCoins(transferCoinsReq, timeout=5)
    except grpc.RpcError as e:
        click.echo(e.details())
        quit(1)
    except Exception as e:
        click.echo("Unhandled error: {}".format(str(e)))
        quit(1)

    txblob = bin2hstr(transferCoinsResp.extended_transaction_unsigned.tx.SerializeToString())
    print(txblob)


@qrl.command()
@click.option('--src', default='', prompt=True, help='source address or index')
@click.option('--master', default='', prompt=True, help='master QRL address')
@click.option('--number_of_slaves', default=0, type=int, prompt=True, help='Number of slaves addresses')
@click.option('--access_type', default=0, type=int, prompt=True, help='0 - All Permission, 1 - Only Mining Permission')
@click.option('--fee', default=0.0, type=float, prompt=True, help='fee (Quanta)')
@click.option('--pk', default=0, prompt=False, help='public key (when local wallet is missing)')
@click.option('--otsidx', default=0, prompt=False, help='OTS index (when local wallet is missing)')
@click.pass_context
def slave_tx_generate(ctx, src, master, number_of_slaves, access_type, fee, pk, otsidx):
    """
    Generates Slave Transaction for the wallet
    """
    try:
        _, src_xmss = _select_wallet(ctx, src)
        src_xmss.set_ots_index(otsidx)
        if src_xmss:
            address_src_pk = src_xmss.pk
        else:
            address_src_pk = pk.encode()

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
        print("Generating Slave #" + str(i + 1))
        xmss = XMSS.from_height(config.dev.xmss_tree_height)
        slave_xmss.append(xmss)
        slave_xmss_seed.append(xmss.extended_seed)
        slave_pks.append(xmss.pk)
        access_types.append(access_type)
        print("Successfully Generated Slave %s/%s" % (str(i + 1), number_of_slaves))

    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    # FIXME: This could be problematic. Check
    slaveTxnReq = qrl_pb2.SlaveTxnReq(slave_pks=slave_pks,
                                      access_types=access_types,
                                      fee=fee_shor,
                                      xmss_pk=address_src_pk,
                                      master_addr=master.encode())

    try:
        slaveTxnResp = stub.GetSlaveTxn(slaveTxnReq, timeout=5)
        tx = Transaction.from_pbdata(slaveTxnResp.extended_transaction_unsigned.tx)
        tx.sign(src_xmss)
        with open('slaves.json', 'w') as f:
            json.dump([bin2hstr(src_xmss.address), slave_xmss_seed, tx.to_json()], f)
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
    if len(tx.signature) == 0:
        click.echo('Signature missing')
        quit(1)

    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
    pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)
    print(pushTransactionResp.error_code)


@qrl.command()
@click.option('--src', default='', prompt=True, help='signer QRL address')
@click.option('--master', default='', prompt=True, help='master QRL address')
@click.option('--dst', type=str, prompt=True, help='List of destination addresses')
@click.option('--amounts', type=str, prompt=True, help='List of amounts to transfer (Quanta)')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.option('--ots_key_index', default=0, prompt=True, help='OTS key Index')
@click.pass_context
def tx_transfer(ctx, src, master, dst, amounts, fee, ots_key_index):
    """
    Transfer coins from src to dst
    """
    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    try:
        _, src_xmss = _select_wallet(ctx, src)
        if not src_xmss:
            click.echo("A local wallet is required to sign the transaction")
            quit(1)

        address_src_pk = src_xmss.pk
        src_xmss.set_ots_index(ots_key_index)
        addresses_dst = []
        for addr in dst.split(' '):
            addresses_dst.append(bytes(hstr2bin(addr[1:])))

        shor_amounts = []
        for amount in amounts.split(' '):
            shor_amounts.append(int(float(amount) * 1.e9))

        fee_shor = int(fee * 1.e9)
    except Exception:
        click.echo("Error validating arguments")
        quit(1)

    try:
        channel = grpc.insecure_channel(ctx.obj.node_public_address)
        stub = qrl_pb2_grpc.PublicAPIStub(channel)
        transferCoinsReq = qrl_pb2.TransferCoinsReq(addresses_to=addresses_dst,
                                                    amounts=shor_amounts,
                                                    fee=fee_shor,
                                                    xmss_pk=address_src_pk,
                                                    master_addr=master.encode())

        transferCoinsResp = stub.TransferCoins(transferCoinsReq, timeout=5)

        tx = Transaction.from_pbdata(transferCoinsResp.extended_transaction_unsigned.tx)
        tx.sign(src_xmss)

        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)

        print(pushTransactionResp)
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--src', default='', prompt=True, help='source QRL address')
@click.option('--master', default='', prompt=True, help='master QRL address')
@click.option('--symbol', default='', prompt=True, help='Symbol Name')
@click.option('--name', default='', prompt=True, help='Token Name')
@click.option('--owner', default='', prompt=True, help='Owner QRL address')
@click.option('--decimals', default=0, prompt=True, help='decimals')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.option('--ots_key_index', default=0, prompt=True, help='OTS key Index')
@click.pass_context
def tx_token(ctx, src, master, symbol, name, owner, decimals, fee, ots_key_index):
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
        amount = int(click.prompt('Amount ')) * (10 ** int(decimals))
        initial_balances.append(qrl_pb2.AddressAmount(address=bytes(hstr2bin(address)),
                                                      amount=amount))

    try:
        _, src_xmss = _select_wallet(ctx, src)
        if not src_xmss:
            click.echo("A local wallet is required to sign the transaction")
            quit(1)

        address_src_pk = src_xmss.pk
        src_xmss.set_ots_index(int(ots_key_index))
        address_owner = bytes(hstr2bin(owner[1:]))
        # FIXME: This could be problematic. Check
        fee_shor = int(fee * 1.e9)
    except KeyboardInterrupt:
        click.echo("Error validating arguments")
        quit(1)

    try:
        channel = grpc.insecure_channel(ctx.obj.node_public_address)
        stub = qrl_pb2_grpc.PublicAPIStub(channel)

        tx = TokenTransaction.create(symbol=symbol.encode(),
                                     name=name.encode(),
                                     owner=address_owner,
                                     decimals=decimals,
                                     initial_balances=initial_balances,
                                     fee=fee_shor,
                                     xmss_pk=address_src_pk,
                                     master_addr=master.encode())

        tx.sign(src_xmss)

        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)

        print(pushTransactionResp.error_code)
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--src', default='', prompt=True, help='source QRL address')
@click.option('--master', default='', prompt=True, help='master QRL address')
@click.option('--token_txhash', default='', prompt=True, help='Token Txhash')
@click.option('--dst', type=str, prompt=True, help='List of destination addresses')
@click.option('--amounts', type=str, prompt=True, help='List of amounts to transfer (Quanta)')
@click.option('--decimals', default=0, prompt=True, help='decimals')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.option('--ots_key_index', default=0, prompt=True, help='OTS key Index')
@click.pass_context
def tx_transfertoken(ctx, src, master, token_txhash, dst, amounts, decimals, fee, ots_key_index):
    """
    Create Token Transaction, that results into the formation of new token if accepted.
    """

    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    try:
        _, src_xmss = _select_wallet(ctx, src)
        if not src_xmss:
            click.echo("A local wallet is required to sign the transaction")
            quit(1)

        address_src_pk = src_xmss.pk
        src_xmss.set_ots_index(int(ots_key_index))
        addresses_dst = []
        for addr in dst.split(' '):
            addresses_dst.append(bytes(hstr2bin(addr[1:])))

        shor_amounts = []
        for amount in amounts.split(' '):
            shor_amounts.append(int(float(amount) * (10 ** int(decimals))))

        bin_token_txhash = bytes(hstr2bin(token_txhash))
        # FIXME: This could be problematic. Check
        fee_shor = int(fee * 1.e9)
    except KeyboardInterrupt as e:
        click.echo("Error validating arguments")
        quit(1)

    try:
        channel = grpc.insecure_channel(ctx.obj.node_public_address)
        stub = qrl_pb2_grpc.PublicAPIStub(channel)

        tx = TransferTokenTransaction.create(token_txhash=bin_token_txhash,
                                             addrs_to=addresses_dst,
                                             amounts=amounts,
                                             fee=fee_shor,
                                             xmss_pk=address_src_pk,
                                             master_addr=master.encode())
        tx.sign(src_xmss)

        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)

        print(pushTransactionResp.error_code)
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
            click.echo('Hash: %s' % (token_hash,))
            click.echo('Balance: %s' % (addressStateResp.state.tokens[token_hash],))
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--msg_id', default='', type=str, prompt=True, help='Message ID')
@click.pass_context
def collect(ctx, msg_id):
    """
    Collects and returns the list of encrypted ephemeral message corresponding to msg_id
    :param ctx:
    :param msg_id:
    :return:
    """
    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)

    try:
        collectEphemeralMessageReq = qrl_pb2.CollectEphemeralMessageReq(msg_id=bytes(hstr2bin(msg_id)))
        collectEphemeralMessageResp = stub.CollectEphemeralMessage(collectEphemeralMessageReq, timeout=5)

        print(len(collectEphemeralMessageResp.ephemeral_metadata.encrypted_ephemeral_message_list))
        for message in collectEphemeralMessageResp.ephemeral_metadata.encrypted_ephemeral_message_list:
            print('%s' % (message.payload,))
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--msg_id', default='', type=str, prompt=True, help='Message ID')
@click.option('--ttl', default=0, type=int, prompt=True, help='Time to Live')
@click.option('--ttr', default=0, type=int, prompt=True, help='Time to Relay')
@click.option('--enc_aes256_symkey', default='', type=str, prompt=True, help='Encrypted AES256 symmetric key')
@click.option('--nonce', default=0, type=int, prompt=True, help='nonce')
@click.option('--payload', default='', type=str, prompt=True, help='Encrypted Payload')
@click.pass_context
def send_eph_message(ctx, msg_id, ttl, ttr, enc_aes256_symkey, nonce, payload):
    """
    Creates & Push Ephemeral Message
    :param ctx:
    :param msg_id:
    :param ttl:
    :param ttr:
    :param enc_aes256_symkey:
    :param nonce:
    :param payload:
    :return:
    """
    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)

    if len(enc_aes256_symkey):
        enc_aes256_symkey = enc_aes256_symkey.encode()

    payload = payload.encode()

    encrypted_ephemeral_msg = EncryptedEphemeralMessage.create(bytes(hstr2bin(msg_id)),
                                                               ttl,
                                                               ttr,
                                                               nonce,
                                                               payload,
                                                               enc_aes256_symkey)

    try:
        ephemeralMessageReq = qrl_pb2.PushEphemeralMessageReq(ephemeral_message=encrypted_ephemeral_msg.pbdata)
        ephemeralMessageResp = stub.PushEphemeralMessage(ephemeralMessageReq, timeout=5)

        print(ephemeralMessageResp.error_code)
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.option('--src', default='', prompt=True, help='source QRL address')
@click.option('--master', default='', prompt=True, help='master QRL address')
@click.option('--kyber-pk', default='', prompt=True, help='kyber public key')
@click.option('--dilithium-pk', default='', prompt=True, help='dilithium public key')
@click.option('--fee', default=0.0, prompt=True, help='fee in Quanta')
@click.option('--ots_key_index', default=0, prompt=True, help='OTS key Index')
@click.pass_context
def tx_latticepk(ctx, src, master, kyber_pk, dilithium_pk, fee, ots_key_index):
    """
    Create Lattice Public Keys Transaction
    """
    if not ctx.obj.remote:
        click.echo('This command is unsupported for local wallets')
        return

    stub = qrl_pb2_grpc.PublicAPIStub(ctx.obj.channel_public)

    try:
        _, src_xmss = _select_wallet(ctx, src)
        if not src_xmss:
            click.echo("A local wallet is required to sign the transaction")
            quit(1)

        address_src_pk = src_xmss.pk
        src_xmss.set_ots_index(ots_key_index)
        kyber_pk = kyber_pk.encode()
        dilithium_pk = dilithium_pk.encode()
        # FIXME: This could be problematic. Check
        fee_shor = int(fee * 1.e9)
    except Exception:
        click.echo("Error validating arguments")
        quit(1)

    try:
        tx = LatticePublicKey.create(fee=fee_shor,
                                     kyber_pk=kyber_pk,
                                     dilithium_pk=dilithium_pk,
                                     xmss_pk=address_src_pk,
                                     master_addr=master.encode())
        tx.sign(src_xmss)

        pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
        pushTransactionResp = stub.PushTransaction(pushTransactionReq, timeout=5)

        print(pushTransactionResp.error_code)
    except Exception as e:
        print("Error {}".format(str(e)))


@qrl.command()
@click.pass_context
def state(ctx):
    """
    Shows Information about a Node's State
    """
    channel = grpc.insecure_channel(ctx.obj.node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)

    nodeStateResp = stub.GetNodeState(qrl_pb2.GetNodeStateReq())

    if ctx.obj.json:
        click.echo(MessageToJson(nodeStateResp))
    else:
        click.echo(nodeStateResp)


def main():
    qrl()


if __name__ == '__main__':
    main()
