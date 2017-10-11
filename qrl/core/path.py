#!/usr/bin/env python
# -*- coding:utf-8 -*-

from os.path import join, pardir, abspath, dirname


class Paths:
    def __init__(self, File=__file__):
        self.ROOT = join(join(dirname(File), pardir), pardir)
        self.REQUIREMENTS = abspath(join(self.ROOT, "requirements.txt"))
