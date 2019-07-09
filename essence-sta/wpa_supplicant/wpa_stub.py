from ctypes import cdll

lib = cdll.LoadLibrary('./wpa_not.so')
message = "Hello. How are you?"
lib.run_wpa_not(message)
