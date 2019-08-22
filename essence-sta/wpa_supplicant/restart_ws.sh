pkill -9 wpa_supplicant
ifconfig wlan1 down
ifconfig wlan1 up
./wpa_supplicant -iwlan1 -c/etc/wpa_supplicant/wpa_supplicant.conf -dd
#sleep 5
#python pystub_sta.py
