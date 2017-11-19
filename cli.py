import grpc
from qrl.generated import qrl_pb2_grpc, qrl_pb2
from pyqrllib.pyqrllib import hstr2bin, mnemonic2bin
from qrl.core.Wallet import Wallet
from qrl.core.Transaction import Transaction
from time import sleep
import click

future_response = None

def get_wallet_obj():
    click.echo('Loading Wallet')
    walletObj = Wallet()
    walletObj._read_wallet()

    return walletObj

def _callback(response_future):
    global future_response
    if response_future.code()== grpc.StatusCode.OK:
        future_response = response_future.result()
        return
    else:
        future_response = False
        print('Error: Seems like you are not running QRL NODE')

#TODO add balance
def print_wallet_list(walletObj):
    pos = 1
    print('Number\t\tAddress')
    for addr in walletObj.address_bundle:
        print('%s\t\t%s' % (pos, addr.address.decode()))
        pos += 1

def select_wallet(walletObj):
    walletnum = click.prompt('Enter wallet number ', type=int)
    if walletnum > len(walletObj.address_bundle) or walletnum <=0:
        print('Invalid Wallet Number')
        return None

    return walletObj.address_bundle[walletnum - 1]

def get_channel():
    return grpc.insecure_channel('127.0.0.1:9009')

@click.group()
def wallet():
    """Wallet Commands
    """
    pass

@wallet.command()
def list():
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
    seed = click.prompt('Please enter your %s' %(seed_type,))
    seed = seed.lower().strip()

    if seed_type == 'mnemonic':
        words = seed.split()
        if len(words) != 32:
            print('You have entered %s words' %(len(words),))
            print('Mnemonic seed must contain only 32 words')
            return
        bin_seed = mnemonic2bin(seed)
    else:
        if len(seed) != 96:
            print('You have entered hexseed of %s characters' %(len(seed),))
            print('Hexseed must be of only 96 characters.')
            return
        bin_seed = hstr2bin(seed)

    walletObj = get_wallet_obj()
    addrBundle = walletObj.get_new_address(seed=bin_seed)
    print('Recovered Wallet Address : %s' %(addrBundle.address.decode(), ))
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
    click.echo('Wallet Address : %s' %(addressBundle.address.decode(),))
    click.echo('Hexseed : %s' %(addressBundle.xmss.get_hexseed(),))
    click.echo('Mnemonic : %s' %(addressBundle.xmss.get_mnemonic(),))

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
    if not selected_wallet:
        return
    print('Wallet Address : %s' %(selected_wallet.address.decode(),))
    print('Hexseed : %s' %(selected_wallet.xmss.get_hexseed(),))
    

@wallet.command()
def mnemonic():
    """
    Provides the mnemonic words of the address into wallet list.
    """
    walletObj = get_wallet_obj()
    print_wallet_list(walletObj)
    selected_wallet = select_wallet(walletObj)
    if not selected_wallet:
        return
    print('Wallet Address : %s' %(selected_wallet.address.decode(),))
    print('Mnemonic : %s' %(selected_wallet.xmss.get_mnemonic(),))

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
    int_amount = int(amount * 10**8)
    int_fee = int(fee * 10**8)
    transferCoinsReq = qrl_pb2.TransferCoinsReq()
    transferCoinsReq.address_from = selected_wallet.address
    transferCoinsReq.address_to = address_to
    transferCoinsReq.amount = int_amount
    transferCoinsReq.fee = int_fee
    transferCoinsReq.xmss_pk = selected_wallet.xmss.pk()
    transferCoinsReq.xmss_ots_index = selected_wallet.xmss.get_index()

    f = stub.TransferCoins.future(transferCoinsReq, timeout=5)
    f.add_done_callback(_callback)
    global future_response
    while future_response == None:
        sleep(6)
    if future_response == False:
        return
    transferCoinsResp = future_response
    future_response = None
    tx = Transaction.from_pbdata(transferCoinsResp.transaction_unsigned)
    tx.sign(selected_wallet.xmss)
    pushTransactionReq = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
    f = stub.PushTransaction.future(pushTransactionReq, timeout=5)
    f.add_done_callback(_callback)
    while future_response == None:
        sleep(6)
    if future_response == False:
        return
    pushTransactionResp = future_response
    print('%s' %(pushTransactionResp.some_response,))


if __name__ == '__main__':
    wallet()
