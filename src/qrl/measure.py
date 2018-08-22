import time
import multiprocessing
from pyqryptonight.pyqryptonight import Qryptominer


def measure(threads):
    class CustomQMiner(Qryptominer):
        def __init__(self):
            Qryptominer.__init__(self)

        def solutionEvent(self, nonce):
            print("Hey a solution has been found!", nonce)
            self.python_nonce = nonce

    input_bytes = [0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09,
                   0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09,
                   0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07, 0x09, 0x03, 0x05, 0x07]
    target = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]

    # Create a customized miner
    qm = CustomQMiner()

    # Set input bytes, nonce
    qm.start(input=input_bytes,
             nonceOffset=0,
             target=target,
             thread_count=threads)

    # Python can sleep or do something else.. the callback will happen in the background
    time.sleep(2)

    return qm.hashRate()


def main():
    cpu_count = multiprocessing.cpu_count()
    for threads in range(1, cpu_count + 1):
        m = []
        for _ in range(3):
            print('.', end='', flush=True)
            m.append(measure(threads))
        print("threads: {:>3}/{:>3}  avg: {:7.2f}H/s    {}]".format(threads, cpu_count, sum(m) / 3, m))


if __name__ == '__main__':
    main()
