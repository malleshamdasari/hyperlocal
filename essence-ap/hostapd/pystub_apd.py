import time
import socket
import sys
from ctypes import cdll
from thread import *

lib = cdll.LoadLibrary('./notifier.so')

message = "PUSH 00:e0:4c:7d:f1:ac 0 I am good, thank you! :ENDNOT:"

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
            print "Data received: ", data
            print "MAC ID: ", data[:17]
            print "Query ID: ", data[17]
            print "Payload: ", data[18:]
            time.sleep(0.5)
            lib.not_process_command(message)

start_new_thread(start_pystub_listener, (0,))

lib.wpa_not_init(0, 0)
