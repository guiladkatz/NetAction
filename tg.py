#!/usr/bin/env python
import argparse, grpc, sys, os, socket, random, struct, time

from time import sleep
import time
import Queue
import socket
import struct
from scapy.all import *
import thread
import csv
from fcntl import ioctl
import IN

SIOCGIFMTU = 0x8921
SIOCSIFMTU = 0x8922



def flow_gen(dst_ip, size):
    flow_dst_ip = dst_ip
    flow_size = size + "K"
    packet_lenght = "0.5K"
    bw = "10K"

    cmd = "iperf -u -c "
    cmd += dst_ip
    cmd += " -n "
    cmd += flow_size
    cmd += " -l "
    cmd += packet_lenght
    cmd += " -b "
    cmd += bw
    os.system(cmd)

def main():
    first_line = True
    with open('flows.csv') as csvfile:
        flows = csv.reader(csvfile, quotechar='|')
        for flow in flows:
            if first_line is False:
                thread.start_new_thread(flow_gen,(str(flow[1]),str(flow[2])))
                next_flow = next(flows)
                sleep(float(next_flow[3]) - float(flow[3]))
            else:
                first_line = False

    print("Sender Terminated")
    


if __name__ == '__main__':
    main()
