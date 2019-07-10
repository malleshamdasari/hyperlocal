import time
from ctypes import cdll

lib = cdll.LoadLibrary('./wpa_not.so')

message = "Hello. How are you?"

print lib.wpa_not_init()

time.sleep(1) 

lib.wpa_not_deinit()

#lib.wpa_not_send_prob_req(message)
