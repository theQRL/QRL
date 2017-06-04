import ntplib

ntp_server = 'pool.ntp.org'
version = 3

def getNTP():
	ntp_timestamp = 0
	try:
		c = ntplib.NTPClient()
		response = c.request(ntp_server, version=version)
		ntp_timestamp = int(response.tx_time*1000)
	except Exception as ex:
		printL (( ' Failed to Get NTP timing ' ))
		printL (( ' Reason - ', str(ex) ))
	return ntp_timestamp
