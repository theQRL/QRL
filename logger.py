# Logging file, must be imported by other programs, 
# in order to log informations into log file

__author__ = 'cyyber'
import logging
import sys
from logging.handlers import RotatingFileHandler

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s(%(lineno)d) - %(message)s')
no_formatter = logging.Formatter('%(message)s')

logFileName = 'qrl.log'

my_handler = RotatingFileHandler(logFileName, mode='a', maxBytes=100*1024*1024, 
                                 backupCount=2, encoding=None, delay=0)
my_handler.setFormatter(log_formatter)
my_handler.setLevel(logging.INFO)

class PrintHelper:
	def __init__(self, logger):
		self.logger = logger

	def printL(self, data, enableLogging=True):
		if type(data) != str:
			data = map(str, data)
			data = " ".join(data)
		if enableLogging:
			self.logger.info(data)
		print data

def getLogger(name):
	logger = logging.getLogger(name)
	logger.setLevel(logging.INFO)
	logger.addHandler(my_handler)
	return logger

