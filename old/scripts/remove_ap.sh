cp /etc/dhcpcd.conf.orig /etc/dhcpcd.conf
cp /etc/dnsmasq.conf.orig /etc/dnsmasq.conf
systemctl restart dhcpcd
systemctl reload dnsmasq
