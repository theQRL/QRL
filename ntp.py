import sys
from time import time
import ntplib

ntp_server = 'pool.ntp.org'
version = 3
times = 5
offset = None
def get_ntp_response():
	try:
		c = ntplib.NTPClient()
		response = c.request(ntp_server, version=version)
	except Exception as ex:
		printL (( ' Failed to Get NTP timing ' ))
		printL (( ' Reason - ', str(ex) ))
		sys.exit(0)
		return None
	return response

def getNTP():
	ntp_timestamp = 0
	response = get_ntp_response()
	if response:
		ntp_timestamp = int(response.tx_time)
	return ntp_timestamp

def setOffset():
	global offset
	response = get_ntp_response()
	if not response:
		return response
	offset = response.offset

def getTime():
	global offset
	curr_time = offset + int(time())
	return curr_time
