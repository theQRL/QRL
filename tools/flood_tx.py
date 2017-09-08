# coding=utf-8
from time import sleep
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1',2000))
data = s.recv(1024)

to_address = 'Q3d24023dc38cafb29aaa9ae7753b8979b31706a319ee6306f47e03751bd128fcbe09'
amount = 100

tx_per_sleep = 1
i = 5
try:
    while True:
        s.sendall('send 0 '+to_address+' '+str(amount))
        data = s.recv(1024)
        print(data)
        i += 1
        if i == tx_per_sleep:
            i = 1
            sleep(1)

except:
    pass

s.close()
