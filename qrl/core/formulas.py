import decimal

from math import log

from qrl.core import config


def calc_coeff(N_tot, block_tot):
    # TODO: This is more related to the way QRL works.. Move to another place
    # TODO: Verify these values and formula
    """
    block reward calculation
    decay curve: 200 years (until 2217AD, 140155555 blocks at 45 seconds block-times)

    N_tot is less the initial coin supply.
    :param N_tot:
    :param block_tot:
    :return:
    >>> calc_coeff(1, 1)
    0.0
    """
    return log(N_tot) / block_tot


def remaining_emission(N_tot, block_n):
    # TODO: This is more related to the way QRL works.. Move to another place
    """
    calculate remaining emission at block_n: N=total initial coin supply, coeff = decay constant
    need to use decimal as floating point not precise enough on different platforms..
    :param N_tot:
    :param block_n:
    :return:

    >>> remaining_emission(1, 1)
    Decimal('0.99999988')
    """
    
    coeff = calc_coeff(config.dev.total_coin_supply - 65000000, 140155555)
    # FIXME:
    #This magic number here should be a function of block time which should be easily changed somewhere
    #By not doing this, it becomes exceedingly difficult to change block time in the future

    # FIXME: Magic number? Unify
    return decimal.Decimal(N_tot * decimal.Decimal(-coeff * block_n).exp()) \
        .quantize(decimal.Decimal('1.00000000'), rounding=decimal.ROUND_HALF_UP)


def block_reward_calc(block_number):
    """
    return block reward for the block_n
    :return:
    """

    # FIXME: Magic number? Unify
    return int((remaining_emission(config.dev.total_coin_supply - 65000000, block_number - 1)
                - remaining_emission(config.dev.total_coin_supply - 65000000, block_number)) * 100000000)

#Note: if config.dev.total_coin_supply is used anywhere else to validate the reward, it should be changed
#to subtract the initial mint in genesis. This merge might require changes elsewhere