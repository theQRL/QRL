# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import datetime
import decimal
from decimal import Decimal

from qrl.core import config

START_DATE = datetime.datetime(2018, 4, 1, 0, 0, 0)
END_DATE = datetime.datetime(2218, 4, 1, 0, 0, 0)
c = END_DATE - START_DATE
TOTAL_MINUTES = divmod(c.days * 86400 + c.seconds, 60)[0]

# At 1 block per minute
TOTAL_BLOCKS = Decimal(TOTAL_MINUTES)


def calc_coeff() -> Decimal:
    """
    block reward calculation. Decay curve: 200 years
    >>> calc_coeff()
    Decimal('1.664087503734056374552843909E-7')
    """
    return config.dev.coin_remaning_at_genesis.ln() / TOTAL_BLOCKS


def remaining_emission(block_n) -> Decimal:
    # TODO: This is more related to the way QRL works.. Move to another place
    """
    calculate remaining emission at block_n: N=total initial coin supply, coeff = decay constant
    need to use decimal as floating point not precise enough on different platforms..
    :param block_n:
    :return:

    >>> remaining_emission(0)
    Decimal('40000000000000000')
    >>> remaining_emission(1)
    Decimal('39999993343650538')
    >>> remaining_emission(2)
    Decimal('39999986687302185')
    >>> remaining_emission(100)
    Decimal('39999334370536850')
    """
    coeff = calc_coeff()
    return (config.dev.coin_remaning_at_genesis * config.dev.shor_per_quanta * Decimal(-coeff * block_n).exp()) \
        .quantize(Decimal('1.'), rounding=decimal.ROUND_DOWN)


def block_reward(block_number) -> Decimal:
    """
    :return: Block reward in shors for block number

    >>> block_reward(1)
    Decimal('6656349462')
    >>> block_reward(2)
    Decimal('6656348353')
    >>> block_reward(3)
    Decimal('6656347246')
    >>> N = 40
    >>> tmp_sum = sum(block_reward(b) for b in range(1, N))
    >>> tmp_est = remaining_emission(0) - remaining_emission(N-1)
    >>> tmp_est - tmp_sum
    Decimal('0')
    """
    return remaining_emission(block_number - 1) - remaining_emission(block_number)
