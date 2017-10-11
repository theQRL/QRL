#!/usr/bin/env python3
# coding=utf-8

# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
from qrl.core.checker import RequirementsChecker


if __name__ == '__main__':
    RequirementsChecker()

    from qrl.main import main
    main()
