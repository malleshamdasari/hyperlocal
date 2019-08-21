import time
import socket
import sys
from ctypes import cdll
from thread import *

lib = cdll.LoadLibrary('./notifier.so')

message = "PUSH ff:ff:ff:ff:ff:ff 0 00000 :ENDNOT:"
#message = "PUSH 00:e0:4c:66:7f:85 1 00000 :ENDNOT:"
#message = "PUSH 00:e0:4c:04:af:01 1 00000 :ENDNOT:"

def start_pystub_listener(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
    	s.bind(("localhost", 9998))
    except socket.error as msg:
    	print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    	sys.exit()
    	
    s.listen(10)
    conn, addr = s.accept()

    while True:
        data = conn.recv(1024)
        if len(data) > 0:
            print data

start_new_thread(start_pystub_listener, (0,))

time.sleep(1)

lib.wpa_not_init()

time.sleep(1)

#lib.not_process_command(message)

while (1):
    time.sleep(10)

lib.wpa_not_deinit()
