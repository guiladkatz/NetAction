#!/usr/bin/env python
import argparse, grpc, sys, os, socket, random, struct, time

from time import sleep
import time
import Queue
import socket
import struct
from scapy.all import *
import matplotlib.pyplot as plt
import thread
import csv
from fcntl import ioctl
import IN

AVERAGE_NUM = 30
AVERAGE_NUM2 = 1

def main():

    time_list_deletions = []
    data_list_deletions = []
    new_data_list_deletions = []
    time_list_insertions = []
    data_list_insertions = []
    new_data_list_insertions = []
    time_list_LU = []
    data_list_LU = []
    new_data_list_LU = []
    time_list_AR = []
    data_list_AR = []
    new_data_list_AR = []

    with open("Deletions_128_64_64.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_deletions.append(float(new_line[0]))
            data_list_deletions.append(float(new_line[1]))
    with open("Insertions_128_64_64.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_insertions.append(float(new_line[0]))
            data_list_insertions.append(float(new_line[1]))
    with open("link_utilization_128_64_64.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU.append(float(new_line[0]))
            data_list_LU.append(float(new_line[1]))
    with open("traffic_arrival_rate_128_64_64.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_AR.append(float(new_line[0]))
            data_list_AR.append(float(new_line[1]))

    for i in range(len(data_list_LU)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU.append(sum(data_list_LU[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            new_data_list_LU.append(data_list_LU[i])

    for i in range(len(data_list_AR)):
        if (i>=AVERAGE_NUM):
            new_data_list_AR.append(sum(data_list_AR[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            new_data_list_AR.append(data_list_AR[i])
    for i in range(len(data_list_deletions)):
        if (i>=AVERAGE_NUM2):
            new_data_list_deletions.append(sum(data_list_deletions[i-AVERAGE_NUM2:i])/AVERAGE_NUM2)
        else:
            new_data_list_deletions.append(sum(data_list_deletions[i:i+AVERAGE_NUM2])/AVERAGE_NUM2)
    for i in range(len(data_list_insertions)):
        if (i>=AVERAGE_NUM2):
            new_data_list_insertions.append(sum(data_list_insertions[i-AVERAGE_NUM2:i])/AVERAGE_NUM2)
        else:
            new_data_list_insertions.append(sum(data_list_insertions[i:i+AVERAGE_NUM2])/AVERAGE_NUM2)




    ##########
    fig, (ax1,ax2) = plt.subplots(2,1)
    title ="Cache Size = 128\nController Miss Threshold = 64\nRandom Rules Sampling Number = 64"
    fig.suptitle(title)
    # make a plot
    ax1.plot(time_list_AR,new_data_list_LU,color='blue')
    ax1.plot(time_list_AR,new_data_list_AR,color='red')
    ax1.legend(["Link Utilization","Traffic Arrival Rate"])
    # set x-axis label
    #ax1.set_xlabel("Simulation Time",fontsize=14)
    # set y-axis label
    #ax1.set_ylabel("Traffic Arrival Rate",color="red",fontsize=14)
    # make a plot
    #ax3=ax1.twinx()
    # make a plot with different y-axis using second axis object
    #ax3.plot(time_list_AR, new_data_list_LU,color="blue")
    #ax3.set_ylabel("Link Utilization",color="blue",fontsize=14)
    #plt.show()
    
    #plt.title("Inserts and Deletes")
    ax2.plot(time_list_deletions,new_data_list_deletions)
    ax2.plot(time_list_deletions,new_data_list_insertions)
    ax2.legend(["Deletes","Inserts"])
    ax2.set_xlabel("Simulation Time [Seconds]")
    ax2.set_ylabel('Number of Events')
    fig.show()
    plt.show()


if __name__ == '__main__':
    main()
