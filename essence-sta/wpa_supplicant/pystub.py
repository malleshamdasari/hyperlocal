import time
from ctypes import cdll

lib = cdll.LoadLibrary('./wpa_not.so')

message = "prob_req"

print lib.wpa_not_init()

time.sleep(1) 

lib.wpa_not_process_command(message)

lib.wpa_not_deinit()

#lib.wpa_not_send_prob_req(message)
