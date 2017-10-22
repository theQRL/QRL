import decimal

from math import log

from qrl.core import config


def calc_coeff(N_tot, block_tot):
    # TODO: This is more related to the way QRL works.. Move to another place
    # TODO: Verify these values and formula
    """
    block reward calculation
    decay curve: 200 years (until 2217AD, 420480000 blocks at 15s block-times)
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
    Decimal('0.99999996')
    """
    # TODO: Verify these values and formula
    coeff = calc_coeff(config.dev.max_coin_supply, 420480000)

    # FIXME: Magic number? Unify
    return decimal.Decimal(N_tot * decimal.Decimal(-coeff * block_n).exp()) \
        .quantize(decimal.Decimal('1.00000000'), rounding=decimal.ROUND_HALF_UP)


def block_reward_calc(block_number):
    """
    return block reward for the block_n
    :return:
    """

    # FIXME: Magic number? Unify
    return int((remaining_emission(config.dev.max_coin_supply, block_number - 1)
                - remaining_emission(config.dev.max_coin_supply, block_number)) * 100000000)
