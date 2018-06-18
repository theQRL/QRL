# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import os
from configparser import RawConfigParser
from os.path import pardir
from unittest import TestCase

from qrl.core.misc import logger

logger.initialize_default()


class TestHelpers(TestCase):
    THIS_DIR = os.path.dirname(os.path.realpath(__file__))
    PATH_SETUP_CFG = os.path.join(THIS_DIR, pardir, pardir, "setup.cfg")
    PATH_REQUIREMENTS = os.path.join(THIS_DIR, pardir, pardir, "requirements.txt")

    def __init__(self, *args, **kwargs):
        super(TestHelpers, self).__init__(*args, **kwargs)

    def test_setup_requirements(self):
        config = RawConfigParser()
        config.read(self.PATH_SETUP_CFG)

        install_requires_in_file = config.get('options', 'install_requires')
        install_requires = set()
        for item in install_requires_in_file.split():
            install_requires.add(item.strip())

        with open(self.PATH_REQUIREMENTS) as f:
            all_req = f.readlines()
            for r in all_req:
                r = r.strip()
                if r.startswith('#'):
                    continue

                if r not in install_requires:
                    raise Exception("{} not found in setup.cfg".format(r))

                install_requires.remove(r)

        if len(install_requires) > 0:
            raise Exception("Not found in requirements.txt:\n{}".format("\n".join(install_requires)))
