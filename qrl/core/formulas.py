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
    coeff = calc_coeff(config.dev.total_coin_supply - 65000000, 420480000) 
    # FIXME:
    #This magic number here should be a function of block time which should be easily changed somewhere

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

#calculates (*approximately*) how many QRL get minted in a given year
#Takes awhile. Calculate year 1 and year 2 and then use the ratio for inter-year decay.
#Use only for testing purposes
def calc_year(year):
    #uses 45 second block time
    print "Starting year ", year
    summation = 0
    time = 45 #assumes a block takes 45 seconds on average, which is true all the time
    #important to note that by going this route for emission calculation (ie no halvings)
    #it becomes 
    per_day = 24*60*60/45 #Assumes a day is exactly 24 hours, which is not true
    per_year = per_day*365 #Assumes a year is exactly 365 days, which is not true
    start = (per_year*(year-1))+1
    end = (per_year*(year-1))+(1+per_year)
    for n in range(start, end):
        summation += calc(n)/100000000.0
    return summation
