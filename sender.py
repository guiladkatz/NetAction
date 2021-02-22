#!/usr/bin/env python
import argparse, grpc, sys, os, socket, random, struct, time

from time import sleep
import Queue
import socket
import struct
from scapy.all import *
import threading



def fast_flow(time):
    count = 0
    src_mac ='00:00:00:00:01:01'
    dst_mac ='00:00:00:00:01:01'
    src_ip = '10.0.1.1'
    dst_ip = '10.12.12.0'
    src_port = 1234
    dst_port = random.randint(49152,65535)
    pkt = Ether(src=src_mac, dst=dst_mac)
    pkt = pkt / IP(dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
    while count < time:
        count += 1
        sleep(0.05)
        new_dst_ip = dst_ip.split(".")
        #new_dst_ip[3] = str(int(new_dst_ip[3]) + count)
        #if(count == 25):
        #    count = 0
        new_dst_ip[3] = str(int(new_dst_ip[3]) + random.randint(1,20))
        new_dst_ip = ".".join(new_dst_ip)
        pkt[IP].dst = new_dst_ip
        #pkt.show2()
        sendp(pkt, iface="h1-eth0", verbose=False)

def med_flow(time):
    count = 0
    src_mac ='00:00:00:00:01:01'
    dst_mac ='00:00:00:00:01:01'
    src_ip = '10.0.1.1'
    dst_ip = '10.12.13.0'
    src_port = 1234
    dst_port = random.randint(49152,65535)
    pkt = Ether(src=src_mac, dst=dst_mac)
    pkt = pkt / IP(dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
    while count < time:
        sleep(0.1)
        count += 1
        new_dst_ip = dst_ip.split(".")
        #new_dst_ip[3] = str(int(new_dst_ip[3]) + count)
        #if(count == 10):
        #    count = 0
        new_dst_ip[3] = str(int(new_dst_ip[3]) + random.randint(1,10))
        new_dst_ip = ".".join(new_dst_ip)
        pkt[IP].dst = new_dst_ip
        #pkt.show2()
        sendp(pkt, iface="h1-eth0", verbose=False)

def slow_flow(time):
    count = 0
    src_mac ='00:00:00:00:01:01'
    dst_mac ='00:00:00:00:01:01'
    src_ip = '10.0.1.1'
    dst_ip = '10.12.14.0'
    src_port = 1234
    dst_port = random.randint(49152,65535)
    pkt = Ether(src=src_mac, dst=dst_mac)
    pkt = pkt / IP(dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
    while count < time:
        sleep(0.4)
        count += 1
        new_dst_ip = dst_ip.split(".")
        #new_dst_ip[3] = str(int(new_dst_ip[3]) + count)
        #if(count == 10):
        #    count = 0
        new_dst_ip[3] = str(int(new_dst_ip[3]) + random.randint(1,10))
        new_dst_ip = ".".join(new_dst_ip)
        pkt[IP].dst = new_dst_ip
        #pkt.show2()
        sendp(pkt, iface="h1-eth0", verbose=False)



def main():
    try:
        run_time = 1600
        fast_thread = threading.Thread(target=fast_flow, args = (run_time,))
        fast_thread.start()
        med_thread = threading.Thread(target=med_flow, args = (run_time,))
        med_thread.start()
        slow_thread = threading.Thread(target=slow_flow, args = (run_time,))
        slow_thread.start()

        fast_thread.join()
        med_thread.join()
        slow_thread.join()
        print("Sender Terminated")
    except:
        print("Failed starting threads")

if __name__ == '__main__':
    main()
