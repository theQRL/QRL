#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys

import os
import pkg_resources


class DependencyChecker:
    """
    While developing, version mismatches between requirements.txt and what is
    actually in the virtualenv can lead to subtle errors. This class ensures
    upon startup that every package in the Python virtualenv is exactly what was
    specified in requirements.txt.
    """
    @staticmethod
    def _get_requirements_path():
        return os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            os.path.pardir,
                                            os.path.pardir,
                                            os.path.pardir,
                                            os.path.pardir,
                                            "requirements.txt"))

    @staticmethod
    def check():
        requirements_path = DependencyChecker._get_requirements_path()

        requirements = []
        with open(requirements_path, "r") as fp:
            for line in fp.readlines():
                if line.startswith("#"):
                    continue
                requirements.append(line.strip("\n"))

        try:
            pkg_resources.require(requirements)
        except Exception as e:
            sys.exit("dependencies not satisfied, run [pip3 install -r requirements.txt] first. \n {}".format(e))
