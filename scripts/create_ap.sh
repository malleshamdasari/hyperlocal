cp dhcpcd.conf.hl /etc/dhcpcd.conf
cp dnsmasq.conf.hl /etc/dnsmasq.conf
systemctl restart dhcpcd
systemctl reload dnsmasq
