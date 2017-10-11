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
    Decimal('0.99999996')
    """
    # TODO: Verify these values and formula
    #http://www.wolframalpha.com/input/?i=seconds+in+200+years
    #http://www.wolframalpha.com/input/?i=(6.307%C3%9710%5E9)%2F45
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

#calculates (approximately) how many QRL get minted in a year
#Takes awhile. Calculate year 1 and year 2 and then use the ratio for inter-year decay.
#Use only for testing purposes
def calc_year(year):
    #uses 45 second block time
    summation = 0
    time = 45 #assumes a block takes 45 seconds on average, which is true all the time 
    per_day = 24*60*60/time #Assumes a day is exactly 24 hours, which is not true
    per_year = per_day*365 #Assumes a year is exactly 365 days, which is not true
    start = (per_year*(year-1))+1
    end = (per_year*(year-1))+(1+per_year)
    for n in range(start, end):
        summation += block_reward_calc(n)/100000000.0
    return summation

#example usage
"""
year_1 = calc_year(1)
year_2 = calc_year(2)
print("The calculation for number 1 is: ", year_1)
print("The calculation for number 2 is: ", year_2)
interyear_decay = year_2/year_1
summation = year_1 + year_2
prev_emittance = year_2
for n in range(3,201):
    prev_emittance = prev_emittance * interyear_decay
    summation += prev_emittance
    print("emittance for year ", n, " is ", prev_emittance)
print("Total emitted after 200 years: ", summation)


output: https://pastebin.com/7fqbEEQJ
"""