from scapy.all import *

# OUT_IFACE_NAME = "servers_sswitch"
# 
# OUTER_DST_MAC = "dc:dc:dc:dc:dc:dc"
# OUTER_SRC_MAC = "F1:F1:F1:F1:F1:F1"
# OUTER_SRC_IP = "1.1.1.1"
# OUTER_DST_IP = "10.0.0.1"
# INNER_DST_MAC = "A1:A1:A1:A1:A1:A1"
# INNER_SRC_MAC = "F1:F1:F1:F1:F1:F1"
# INNER_DST_IP = "192.168.0.1"
# INNER_SRC_IP = "1.1.1.1"
# 
# pkt = Ether(src=INNER_SRC_MAC, dst=INNER_DST_MAC) / \
#         Dot1Q(vlan=10) / \
#         IP(src=INNER_SRC_IP, dst=INNER_DST_IP) / \
#         TCP(sport=12345, dport=1000)
# 
# pkt.show2()
# 
# sendp(pkt, iface=OUT_IFACE_NAME)

SERVER_IPS = ["1.1.1.1", "2.2.2.2"]

def ip_filter(pkt):
	return pkt['IP'].dst in SERVER_IPS

def swap_and_send_back(pkt):
	pkt.show2()

	tmp = pkt['Ether'].src
	pkt['Ether'].src = pkt['Ether'].dst
	pkt['Ether'].dst = tmp

	tmp = pkt['IP'].src
	pkt['IP'].src = pkt['IP'].dst
	pkt['IP'].dst = tmp

	tmp = pkt['UDP'].sport
	pkt['Ether'].sport = pkt['Ether'].dport
	pkt['Ether'].dport = tmp

	pkt.show2()

	sendp(pkt, iface="servers_sswitch")


sniff(prn=swap_and_send_back, iface="servers_sswitch", lfilter=ip_filter)