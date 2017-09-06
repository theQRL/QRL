#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
import pkg_resources
from qrl.core.path import Paths


class RequireChecker():
    def __init__(self):
        self.requirements = []
        self.paths = Paths()
        self.requirements = self.get_requirements(self.paths.REQUIREMENTS)
        try:
            pkg_resources.require(self.requirements)
        except:
            sys.exit("dependencies not satisfied, run [pip install -r requirements] first.")

    def get_requirements(self, rq_path):
        requirements = []

        with open(rq_path, "r") as fp:
            lines = fp.readlines()
            for line in lines:
                if line.startswith("#"):
                    continue
                else:
                    requirements.append(line.strip("\n"))
        return requirements


RequireChecker()
