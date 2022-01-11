# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import datetime
import decimal
from decimal import Decimal
from qrl.core.config import DevConfig


def get_total_blocks(dev_config: DevConfig):
    START_DATE = datetime.datetime(2018, 4, 1, 0, 0, 0)
    END_DATE = datetime.datetime(2018 + dev_config.complete_emission_time_span_in_years, 4, 1, 0, 0, 0)
    c = END_DATE - START_DATE
    TOTAL_SECONDS = c.days * 86400 + c.seconds
    total_blocks = divmod(TOTAL_SECONDS, dev_config.block_timing_in_seconds)[0]

    # At 1 block per minute
    return Decimal(total_blocks)


def calc_coeff(dev_config: DevConfig) -> Decimal:
    """
    block reward calculation. Decay curve: 200 years

    >>> from qrl.core import config
    >>> calc_coeff(config.dev)
    Decimal('1.664087503734056374552843909E-7')
    """
    return dev_config.coin_remaining_at_genesis.ln() / get_total_blocks(dev_config)


def remaining_emission(block_n, dev_config: DevConfig) -> Decimal:
    # TODO: This is more related to the way QRL works.. Move to another place
    """
    calculate remaining emission at block_n: N=total initial coin supply, coeff = decay constant
    need to use decimal as floating point not precise enough on different platforms..
    :param block_n:
    :return:

    >>> from qrl.core import config
    >>> remaining_emission(0, config.dev)
    Decimal('40000000000000000')
    >>> remaining_emission(1, config.dev)
    Decimal('39999993343650538')
    >>> remaining_emission(2, config.dev)
    Decimal('39999986687302185')
    >>> remaining_emission(100, config.dev)
    Decimal('39999334370536850')
    """

    coeff = calc_coeff(dev_config)
    return (dev_config.coin_remaining_at_genesis * dev_config.shor_per_quanta * Decimal(-coeff * block_n).exp()) \
        .quantize(Decimal('1.'), rounding=decimal.ROUND_DOWN)


def block_reward(block_number: int, dev_config: DevConfig) -> Decimal:
    """
    :return: Block reward in shors for block number

    >>> from qrl.core import config
    >>> block_reward(1, config.dev)
    Decimal('6656349462')
    >>> block_reward(2, config.dev)
    Decimal('6656348353')
    >>> block_reward(3, config.dev)
    Decimal('6656347246')
    >>> N = 40
    >>> tmp_sum = sum(block_reward(b, config.dev) for b in range(1, N))
    >>> tmp_est = remaining_emission(0, config.dev) - remaining_emission(N-1, config.dev)
    >>> tmp_est - tmp_sum
    Decimal('0')
    """
    factor = Decimal('0.4')
    if block_number < dev_config.hard_fork_heights[1]:
        factor = Decimal('1')

    reward = factor * (remaining_emission(block_number - 1, dev_config) - remaining_emission(block_number, dev_config))
    return reward.quantize(Decimal('1.'), rounding=decimal.ROUND_DOWN)
