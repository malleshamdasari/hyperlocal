#!/bin/bash

# set wpa_supplicant debug level to 1, disable timestamps, disable show_keys

LOG="/var/log/wpa_supplicant.log"

./wpa_supplicant -iwlan0 -c/etc/wpa_supplicant/wpa_supplicant.conf -dd -u -f $LOG -B
