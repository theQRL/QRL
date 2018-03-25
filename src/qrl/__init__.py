# -*- coding: utf-8 -*-
import pkg_resources

__all__ = ['core', 'crypto']

try:
    __version__ = pkg_resources.get_distribution(__name__).version
except pkg_resources.DistributionNotFound as e:
    __version__ = 'local-dev'
except Exception as e:
    __version__ = 'unknown'
