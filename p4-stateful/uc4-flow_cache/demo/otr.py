from scapy.all import *

OUT_IFACE_NAME = "otr_sswitch"

OUTER_DST_MAC = "dc:dc:dc:dc:dc:dc"
OUTER_SRC_MAC = "01:01:01:01:01:01"
OUTER_SRC_IP = "10.10.10.10"
OUTER_DST_IP = "10.0.0.1"

SERVER_IPS = ["1.1.1.1", "2.2.2.2"]

def ip_filter(pkt):
	return pkt['IP'].src in SERVER_IPS

def swap_and_send_back(pkt):
	pkt.show2()
 
	encap_pkt = Ether(src=OUTER_SRC_MAC, dst=OUTER_DST_MAC) / \
					IP(src=OUTER_SRC_IP, dst=OUTER_DST_IP) / \
					UDP() / \
        			VXLAN(vni=pkt['Dot1Q'].vlan*10, reserved2=pkt['Dot1Q'].vlan) / \
        			Ether(src=pkt['Ether'].src, dst=pkt['Ether'].dst) / \
        			pkt['IP']

	encap_pkt.show2()

	sendp(encap_pkt, iface=OUT_IFACE_NAME)

sniff(prn=swap_and_send_back, iface=OUT_IFACE_NAME, lfilter=ip_filter)