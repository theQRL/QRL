#!/usr/bin/env python3
import click
import grpc
from pyqrllib.pyqrllib import mnemonic2bin, hstr2bin

from qrl.core.Transaction import Transaction
from qrl.core.Wallet import Wallet
from qrl.generated import qrl_pb2_grpc, qrl_pb2


def get_wallet_obj():
    # FIXME: Not sure we need this redirection here. Maybe avoid
    walletObj = Wallet()
    return walletObj


# TODO add balance
def print_wallet_list(walletObj):
    print('Number\t\tAddress')
    for pos, addr in enumerate(walletObj.address_bundle):
        print('%s\t\t%s' % (pos, addr.address.decode()))


def select_wallet(walletObj):
    # FIXME: Get values from arguments, interactive only when necessary
    walletnum = click.prompt('Enter wallet number ', type=int)

    if 0 <= walletnum < len(walletObj.address_bundle):
        return walletObj.address_bundle[walletnum]

    print('Invalid Wallet Number')
    return None


def get_channel():
    return grpc.insecure_channel('127.0.0.1:9009')


@click.group()
def wallet():
    """Wallet Commands
    """
    pass


@wallet.command()
def list():  # FIXME: method name is a python keyword
    """
    Lists available wallets
    """
    walletObj = get_wallet_obj()
    print_wallet_list(walletObj)


@wallet.command()
@click.option('--seed-type', type=click.Choice(['hexseed', 'mnemonic']), default='hexseed')
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

    walletObj = get_wallet_obj()
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


@wallet.command()
def generate():
    """
    Generates new wallet address
    """
    walletObj = get_wallet_obj()
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


@wallet.command()
def hexseed():
    """
    Provides the Hexseed of the address into wallet list.
    """
    walletObj = get_wallet_obj()
    print_wallet_list(walletObj)
    selected_wallet = select_wallet(walletObj)

    if selected_wallet:
        click.echo('Wallet Address : %s' % (selected_wallet.address.decode(),))
        click.echo('Hexseed        : %s' % (selected_wallet.xmss.get_hexseed(),))


@wallet.command()
def mnemonic():
    """
    Provides the mnemonic words of the address into wallet list.
    """
    walletObj = get_wallet_obj()
    print_wallet_list(walletObj)
    selected_wallet = select_wallet(walletObj)

    if selected_wallet:
        click.echo('Wallet Address  : %s' % (selected_wallet.address.decode(),))
        click.echo('Mnemonic        : %s' % (selected_wallet.xmss.get_mnemonic(),))


@wallet.command()
def send():
    """
    Transfer coins
    """
    channel = get_channel()
    stub = qrl_pb2_grpc.PublicAPIStub(channel)

    walletObj = get_wallet_obj()
    print_wallet_list(walletObj)
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


@wallet.command()
def eph():
    # channel = get_channel()
    # stub = qrl_pb2_grpc.PublicAPIStub(channel)

    walletObj = get_wallet_obj()
    print_wallet_list(walletObj)
    selected_wallet = select_wallet(walletObj)
    if not selected_wallet:
        return

    # address_to = click.prompt('Address To', type=str)
    # message = click.prompt('Message', type=str)


@wallet.command()
def lattice():
    channel = get_channel()
    stub = qrl_pb2_grpc.PublicAPIStub(channel)

    walletObj = get_wallet_obj()
    print_wallet_list(walletObj)
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
    wallet()


if __name__ == '__main__':
    main()
