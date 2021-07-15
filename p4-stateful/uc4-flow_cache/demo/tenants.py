from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.vxlan import VXLAN
from scapy.sendrecv import sendp

OUT_IFACE_NAME = "dc_sswitch"

OUTER_SRC_MAC = "dc:dc:dc:dc:dc:dc"
OUTER_DST_MAC = "F1:F1:F1:F1:F1:F1"
OUTER_DST_IP = "10.10.10.10"
OUTER_SRC_IP = "10.0.0.1"
INNER_SRC_MAC = "A1:A1:A1:A1:A1:A1"
INNER_DST_MAC = "E1:E1:E1:E1:E1:E1"
INNER_SRC_IP = "192.168.0.1"
INNER_DST_IP = "1.1.1.1"

pkt = Ether(src=OUTER_SRC_MAC, dst=OUTER_DST_MAC) / \
        IP(src=OUTER_SRC_IP, dst=OUTER_DST_IP) / \
        UDP() / \
        VXLAN(vni=100) / \
        Ether(src=INNER_SRC_MAC, dst=INNER_DST_MAC) / \
        IP(src=INNER_SRC_IP, dst=INNER_DST_IP) / \
        UDP(sport=12345, dport=1000) / \
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

pkt.show2()

sendp(pkt, iface=OUT_IFACE_NAME)
