from unittest import TestCase
from mock import patch

from tests.misc.helper import get_alice_xmss, replacement_getTime

alice = get_alice_xmss()


@patch('qrl.core.misc.ntp.getTime', new=replacement_getTime)
class TestQRLNodeReal(TestCase):
    pass
