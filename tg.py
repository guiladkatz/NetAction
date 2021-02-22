#!/usr/bin/env python
import argparse, grpc, sys, os, socket, random, struct, time

from time import sleep
import time
import Queue
import socket
import struct
from scapy.all import *
import threading
import csv


def tg():
    """
    sock = conf.L2socket()
    pe=Ether()/IP(dst="10.13.37.218")/ICMP()
    data = pe.build()
    while True:
        send(data)
    """
    count = 0
    src_mac ='00:00:00:00:01:01'
    dst_mac ='00:00:00:00:01:01'
    src_ip = '10.0.1.1'
    dst_ip = '10.12.14.0'
    src_port = 1234
    dst_port = random.randint(49152,65535)
    MTU = 1514 - 42
    s = 100000
    pkt = Ether(src=src_mac, dst=dst_mac)
    pkt = pkt / IP(dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
    pkt = pkt / Raw(RandBin(size=2000))
    begin = time.time()
    #for i in range(s/MTU):   
    #    pkt2 = pkt / Raw(RandBin(size=MTU))
        #while True:
    send(pkt, iface="h1-eth0", verbose=False)
    end = time.time()
    print(end-begin)
    """
    for i in range(9000, 9100):
        pkt = Ether()/IP()/Raw("a"*i)
        try:
            print(i)
            print(len(pkt))
            send(pkt)

        except OSError:
            print(i)
            print(len(pkt))
            break
     """



def main():
    """
    try:
        tg_thread = threading.Thread(target=tg)
        tg_thread.start()

        tg_thread.join()
        print("Sender Terminated")
    except:
        print("Failed starting threads")
    """
    with open('packets.csv') as csvfile:
        pkts = csv.reader(csvfile, quotechar='|')
        for row in pkts:
            print(row[0])
            print(row[1])
            print(row[2])
            print(row[3])

if __name__ == '__main__':
    main()
