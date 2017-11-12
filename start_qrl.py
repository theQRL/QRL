#!/usr/bin/env python3
# coding=utf-8

# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core.DependencyChecker import DependencyChecker

DependencyChecker.check()

from qrl.main import main

main()
