#!/usr/bin/python3

from scapy.all import *
import time

pkt = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/UDP(sport=5555, dport=9999)

for i in range(10):
        pkt['UDP'].sport = pkt['UDP'].sport - i*2
        pkt['UDP'].dport = pkt['UDP'].dport + i*3
        sendp(pkt, iface="veth0")
        time.sleep(0.6)

