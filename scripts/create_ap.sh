cp dhcpcd.conf.hl /etc/dhcpcd.conf
cp dnsmasq.conf.hl /etc/dnsmasq.conf
systemctl restart dhcpcd
systemctl reload dnsmasq
cp hostapd.conf.hl /etc/hostapd/hostapd.conf
cp hostapd.hl /etc/defaults/hostapd
systemctl unmask hostapd
systemctl enable hostapd
systemctl start hostapd
cp sysctl.conf.hl /etc/sysctl.conf
iptables -t nat -A  POSTROUTING -o eth0 -j MASQUERADE
sh -c "iptables-save > /etc/iptables.ipv4.nat"
cp rc.local.hl /etc/rc.local
