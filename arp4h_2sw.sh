s1 ifconfig s1-eth3 192.168.0.5 netmask 255.255.255.0 up
s2 ifconfig s2-eth3 192.168.0.2 netmask 255.255.255.0 up
s1 ifconfig s1-eth4 192.168.0.1 netmask 255.255.255.0 up
s1 ifconfig s1-eth4 hw ether 00:aa:00:01:00:02
s2 ifconfig s2-eth3 hw ether 00:aa:00:02:00:03
h5 ifconfig h5-eth0 192.168.0.100 netmask 255.255.255.0 up
h5 ifconfig h5-eth0 hw ether 00:00:00:00:01:05
h1 ip route add 10.0.2.0/24 dev h1-eth0
h2 ip route add 10.0.2.0/24 dev h2-eth0
h3 ip route add 10.0.1.0/24 dev h3-eth0
h4 ip route add 10.0.1.0/24 dev h4-eth0
h1 arp -s 10.0.1.2 00:00:00:00:01:02
h1 arp -s 10.0.2.3 00:00:00:00:02:03
h1 arp -s 10.0.2.4 00:00:00:00:02:04
h2 arp -s 10.0.1.1 00:00:00:00:01:01
h2 arp -s 10.0.2.3 00:00:00:00:02:03
h2 arp -s 10.0.2.4 00:00:00:00:02:04
h3 arp -s 10.0.1.1 00:00:00:00:01:01
h3 arp -s 10.0.1.2 00:00:00:00:01:02
h3 arp -s 10.0.2.4 00:00:00:00:02:04
h4 arp -s 10.0.1.1 00:00:00:00:01:01
h4 arp -s 10.0.1.2 00:00:00:00:01:02
h4 arp -s 10.0.2.3 00:00:00:00:02:03
xterm h5