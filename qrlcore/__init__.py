# -*- coding: utf-8 -*-
import pkg_resources

try:
    __version__ = pkg_resources.get_distribution(__name__).version
except Exception as e:
    print("Version has not been set!", e.message)
    __version__ = 'unknown'
