import time
from ctypes import cdll

lib = cdll.LoadLibrary('./wpa_not.so')

message = "hl_query"

print lib.wpa_not_init()

time.sleep(1) 

lib.wpa_not_process_command(message)

time.sleep(10)

lib.wpa_not_deinit()

