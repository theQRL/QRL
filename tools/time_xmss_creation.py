import time

from qrl.crypto.xmss import XMSS


# Code moved from xmss.py
def measure_xmss_creation_time(n):
    # TODO: Remove this timing helper?
    start_time = time.time()
    z = XMSS(n)
    total_time = time.time() - start_time
    return z, total_time


# Code moved from merkle.py
def measure_xmss_verification_time(s, m):
    start_time = time.time()
    answer = XMSS.VERIFY(m, s)
    total_time = time.time() - start_time
    return answer, total_time


if __name__ == '__main__':
    test_cases = [10, 100, 1000, 10000]

    for tc in test_cases:
        z, creation_time = measure_xmss_creation_time(tc)
        print(tc, creation_time)
